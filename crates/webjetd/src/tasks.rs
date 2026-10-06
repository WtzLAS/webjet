//! Ownership of the agent's long-running tasks.
//!
//! Every loop that must run for the agent's whole life (gossip, sessions,
//! listeners, the data plane, the controller) is started through
//! [`Supervisor::service`]. When such a task ends while the agent is
//! running (it returned, failed or panicked), the agent can't do its job
//! any more, so [`Supervisor::fatal`] resolves and the agent exits with an
//! error; the service manager (systemd, launchd, the Windows SCM, Docker's
//! restart policy) starts it again. Tasks that may legitimately finish go
//! through [`Supervisor::oneshot`]: there only a panic is fatal.
//!
//! At shutdown [`Supervisor::abort_all`] stops every task before the agent
//! persists its state and removes routes and DNS settings, so nothing
//! writes or re-adds them concurrently.
//!
//! Short-lived per-connection tasks are still plain `tokio::spawn`: a panic
//! there ends only that connection, and the panic hook installed by
//! [`install_panic_hook`] logs it.

use parking_lot::Mutex;
use std::future::Future;
use tokio::sync::mpsc;
use tokio::task::AbortHandle;

/// What a task is allowed to do.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    /// Must run until shutdown: ending at all is fatal.
    Service,
    /// May finish; only a panic is fatal, an error is logged.
    Oneshot,
}

/// How a task ended.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum How {
    Returned,
    Failed(String),
    Panicked(String),
    Cancelled,
}

/// A task that ended, as reported to the agent's main loop.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Ended {
    pub name: &'static str,
    pub kind: Kind,
    pub how: How,
}

impl Ended {
    /// Whether the agent must stop because of this.
    pub fn is_fatal(&self) -> bool {
        match (&self.how, self.kind) {
            (How::Cancelled, _) => false,
            (How::Panicked(_), _) => true,
            (_, Kind::Service) => true,
            (How::Returned | How::Failed(_), Kind::Oneshot) => false,
        }
    }
}

impl std::fmt::Display for Ended {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match &self.how {
            How::Returned => write!(f, "task {} stopped", self.name),
            How::Failed(e) => write!(f, "task {} failed: {e}", self.name),
            How::Panicked(p) => write!(f, "task {} panicked: {p}", self.name),
            How::Cancelled => write!(f, "task {} was cancelled", self.name),
        }
    }
}

pub struct Supervisor {
    tx: mpsc::UnboundedSender<Ended>,
    rx: tokio::sync::Mutex<mpsc::UnboundedReceiver<Ended>>,
    handles: Mutex<Vec<(&'static str, AbortHandle)>>,
    stopping: std::sync::atomic::AtomicBool,
}

impl Default for Supervisor {
    fn default() -> Self {
        let (tx, rx) = mpsc::unbounded_channel();
        Supervisor {
            tx,
            rx: tokio::sync::Mutex::new(rx),
            handles: Mutex::new(Vec::new()),
            stopping: std::sync::atomic::AtomicBool::new(false),
        }
    }
}

/// The text of a panic payload.
fn panic_text(p: &(dyn std::any::Any + Send)) -> String {
    if let Some(s) = p.downcast_ref::<&str>() {
        (*s).to_string()
    } else if let Some(s) = p.downcast_ref::<String>() {
        s.clone()
    } else {
        "(non-string panic payload)".to_string()
    }
}

impl Supervisor {
    /// Start a task that must run until shutdown.
    pub fn service<F>(&self, name: &'static str, fut: F)
    where
        F: Future<Output = ()> + Send + 'static,
    {
        self.start(name, Kind::Service, async move {
            fut.await;
            Ok(())
        });
    }

    /// Start a task that must run until shutdown and may fail with an error.
    pub fn service_result<F>(&self, name: &'static str, fut: F)
    where
        F: Future<Output = anyhow::Result<()>> + Send + 'static,
    {
        self.start(name, Kind::Service, fut);
    }

    /// Start a task that may finish on its own; an error is only logged.
    pub fn oneshot<F>(&self, name: &'static str, fut: F)
    where
        F: Future<Output = anyhow::Result<()>> + Send + 'static,
    {
        self.start(name, Kind::Oneshot, fut);
    }

    fn start<F>(&self, name: &'static str, kind: Kind, fut: F)
    where
        F: Future<Output = anyhow::Result<()>> + Send + 'static,
    {
        let inner = tokio::spawn(fut);
        let abort = inner.abort_handle();
        let tx = self.tx.clone();
        tokio::spawn(async move {
            let how = match inner.await {
                Ok(Ok(())) => How::Returned,
                Ok(Err(e)) => How::Failed(format!("{e:#}")),
                Err(e) if e.is_panic() => How::Panicked(panic_text(&*e.into_panic())),
                Err(_) => How::Cancelled,
            };
            let ended = Ended { name, kind, how };
            if !ended.is_fatal() && ended.how != How::Cancelled {
                match &ended.how {
                    How::Failed(_) => tracing::error!("{ended}"),
                    _ => tracing::debug!("{ended}"),
                }
            }
            let _ = tx.send(ended);
        });
        let mut h = self.handles.lock();
        h.retain(|(_, a)| !a.is_finished());
        h.push((name, abort));
    }

    /// Resolves with the first task whose end is fatal (see [`Ended::is_fatal`]).
    /// Never resolves once [`abort_all`](Self::abort_all) has been called.
    pub async fn fatal(&self) -> Ended {
        let mut rx = self.rx.lock().await;
        loop {
            match rx.recv().await {
                Some(e)
                    if e.is_fatal() && !self.stopping.load(std::sync::atomic::Ordering::SeqCst) =>
                {
                    return e;
                }
                Some(_) => {}
                // Unreachable while `self` holds a sender; wait forever.
                None => std::future::pending::<()>().await,
            }
        }
    }

    /// Names of the tasks still running.
    pub fn running(&self) -> Vec<&'static str> {
        let h = self.handles.lock();
        h.iter()
            .filter(|(_, a)| !a.is_finished())
            .map(|(n, _)| *n)
            .collect()
    }

    /// Stop every task (at shutdown). Tasks started afterwards are not
    /// affected, and none of them counts as fatal any more.
    pub fn abort_all(&self) {
        self.stopping
            .store(true, std::sync::atomic::Ordering::SeqCst);
        let h = std::mem::take(&mut *self.handles.lock());
        for (_, a) in h {
            a.abort();
        }
    }
}

/// Log panics through tracing (stdout, JSON when configured), then run the
/// default hook (stderr with the backtrace setting). Installed once.
pub fn install_panic_hook() {
    static ONCE: std::sync::Once = std::sync::Once::new();
    ONCE.call_once(install_hook);
}

fn install_hook() {
    let default = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        let msg = panic_text(info.payload());
        let at = info
            .location()
            .map(|l| format!("{}:{}", l.file(), l.line()))
            .unwrap_or_default();
        tracing::error!(location = %at, "panic: {msg}");
        default(info);
    }));
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    async fn next(s: &Supervisor) -> Ended {
        tokio::time::timeout(Duration::from_secs(5), s.fatal())
            .await
            .expect("a fatal end")
    }

    #[tokio::test]
    async fn a_service_that_returns_is_fatal() {
        let s = Supervisor::default();
        s.service("loop", async {});
        let e = next(&s).await;
        assert_eq!(e.name, "loop");
        assert_eq!(e.how, How::Returned);
    }

    #[tokio::test]
    async fn a_service_that_fails_is_fatal_with_its_error() {
        let s = Supervisor::default();
        s.service_result("listener", async { Err(anyhow::anyhow!("bind: in use")) });
        let e = next(&s).await;
        assert_eq!(e.how, How::Failed("bind: in use".into()));
        assert!(e.to_string().contains("listener failed: bind: in use"));
    }

    #[tokio::test]
    async fn a_panic_is_fatal_even_in_a_oneshot() {
        let s = Supervisor::default();
        s.oneshot("ok", async { Ok(()) });
        s.oneshot("err", async { Err(anyhow::anyhow!("not fatal")) });
        s.oneshot("boom", async {
            let v: Vec<u8> = Vec::new();
            // Index out of bounds: a real panic, not an explicit one.
            let _ = v[std::hint::black_box(3)];
            Ok(())
        });
        let e = next(&s).await;
        assert_eq!(e.name, "boom");
        assert!(matches!(e.how, How::Panicked(ref p) if p.contains("index out of bounds")));
    }

    #[tokio::test]
    async fn oneshots_that_finish_are_not_fatal() {
        let s = Supervisor::default();
        s.oneshot("ok", async { Ok(()) });
        s.oneshot("err", async { Err(anyhow::anyhow!("logged")) });
        assert!(
            tokio::time::timeout(Duration::from_millis(200), s.fatal())
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn abort_all_stops_services_without_a_fatal_end() {
        let s = Supervisor::default();
        let (tx, mut rx) = mpsc::unbounded_channel::<()>();
        s.service("forever", async move {
            let _keep = tx;
            std::future::pending::<()>().await;
        });
        assert_eq!(s.running(), vec!["forever"]);
        s.abort_all();
        // The task's sender is dropped once it's aborted.
        assert!(
            tokio::time::timeout(Duration::from_secs(5), rx.recv())
                .await
                .expect("aborted")
                .is_none()
        );
        assert!(
            tokio::time::timeout(Duration::from_millis(200), s.fatal())
                .await
                .is_err()
        );
        assert!(s.running().is_empty());
    }

    #[test]
    fn fatality_table() {
        let e = |kind, how| Ended {
            name: "t",
            kind,
            how,
        };
        assert!(e(Kind::Service, How::Returned).is_fatal());
        assert!(e(Kind::Service, How::Failed("x".into())).is_fatal());
        assert!(e(Kind::Service, How::Panicked("x".into())).is_fatal());
        assert!(!e(Kind::Service, How::Cancelled).is_fatal());
        assert!(!e(Kind::Oneshot, How::Returned).is_fatal());
        assert!(!e(Kind::Oneshot, How::Failed("x".into())).is_fatal());
        assert!(e(Kind::Oneshot, How::Panicked("x".into())).is_fatal());
        assert!(!e(Kind::Oneshot, How::Cancelled).is_fatal());
    }
}
