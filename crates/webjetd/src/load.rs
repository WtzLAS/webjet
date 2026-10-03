//! Relay load sampling (§11.8.1): process CPU, forwarding utilization and
//! hop queue delay, each averaged over 30 seconds, plus the auto-estimated
//! capacity from the highest sustained throughput.

use std::collections::VecDeque;
use std::time::{Duration, Instant};

/// Window for the advertised averages.
pub const WINDOW: Duration = Duration::from_secs(30);
pub const SAMPLE_EVERY: Duration = Duration::from_secs(2);

/// CPU time used by this process so far (user + system).
pub fn process_cpu_time() -> Option<Duration> {
    imp::process_cpu_time()
}

/// Logical CPUs available to the process.
pub fn cpu_count() -> usize {
    std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(1)
}

#[cfg(unix)]
mod imp {
    use std::time::Duration;
    pub fn process_cpu_time() -> Option<Duration> {
        let mut ru: libc::rusage = unsafe { std::mem::zeroed() };
        if unsafe { libc::getrusage(libc::RUSAGE_SELF, &mut ru) } != 0 {
            return None;
        }
        let tv = |t: libc::timeval| {
            Duration::from_secs(t.tv_sec as u64) + Duration::from_micros(t.tv_usec as u64)
        };
        Some(tv(ru.ru_utime) + tv(ru.ru_stime))
    }
}

#[cfg(windows)]
mod imp {
    use std::time::Duration;
    use windows_sys::Win32::Foundation::FILETIME;
    use windows_sys::Win32::System::Threading::{GetCurrentProcess, GetProcessTimes};
    pub fn process_cpu_time() -> Option<Duration> {
        let z = FILETIME {
            dwLowDateTime: 0,
            dwHighDateTime: 0,
        };
        let (mut c, mut e, mut k, mut u) = (z, z, z, z);
        if unsafe { GetProcessTimes(GetCurrentProcess(), &mut c, &mut e, &mut k, &mut u) } == 0 {
            return None;
        }
        let ft = |f: FILETIME| ((f.dwHighDateTime as u64) << 32 | f.dwLowDateTime as u64) * 100;
        Some(Duration::from_nanos(ft(k) + ft(u)))
    }
}

#[cfg(not(any(unix, windows)))]
mod imp {
    pub fn process_cpu_time() -> Option<std::time::Duration> {
        None
    }
}

#[derive(Clone, Copy, Debug)]
struct Sample {
    at: Instant,
    cpu: Duration,
    bytes: u64,
    queue_ms: f64,
}

/// Rolling samples of the counters the load is computed from.
#[derive(Debug)]
pub struct LoadSampler {
    samples: VecDeque<Sample>,
    cores: usize,
    /// Highest sustained forwarding rate seen (Mbit/s), decaying slowly.
    pub peak_mbps: f64,
    last_peak_decay: Option<Instant>,
}

#[derive(Clone, Copy, Debug, Default, PartialEq)]
pub struct LoadAverages {
    /// Agent CPU as a share of all cores, 0..=100.
    pub cpu_pct: f64,
    /// Bytes per second sent on hops.
    pub tx_bps: f64,
    /// Mean of the sampled worst hop queue delays.
    pub queue_ms: f64,
}

impl Default for LoadSampler {
    fn default() -> Self {
        LoadSampler::new(cpu_count())
    }
}

impl LoadSampler {
    pub fn new(cores: usize) -> Self {
        LoadSampler {
            samples: VecDeque::new(),
            cores: cores.max(1),
            peak_mbps: 0.0,
            last_peak_decay: None,
        }
    }

    /// Record the current counters. `cpu` is the process CPU time,
    /// `bytes` the total bytes sent on hops, `queue_ms` the worst hop queue
    /// delay right now.
    pub fn record(&mut self, at: Instant, cpu: Duration, bytes: u64, queue_ms: f64) {
        self.samples.push_back(Sample {
            at,
            cpu,
            bytes,
            queue_ms,
        });
        while self.samples.len() > 2
            && self
                .samples
                .front()
                .map(|s| at.duration_since(s.at) > WINDOW)
                .unwrap_or(false)
        {
            self.samples.pop_front();
        }
        // Capacity estimate: the highest throughput sustained over a window
        // (§11.8.1), decaying by 1% per hour so a one-off burst ages out.
        if let Some(avg) = self.averages() {
            let mbps = avg.tx_bps * 8.0 / 1e6;
            if self.window_full() && mbps > self.peak_mbps {
                self.peak_mbps = mbps;
            }
        }
        let decay_due = self
            .last_peak_decay
            .map(|t| at.duration_since(t) >= Duration::from_secs(3600))
            .unwrap_or(true);
        if decay_due {
            self.peak_mbps *= 0.99;
            self.last_peak_decay = Some(at);
        }
    }

    fn window_full(&self) -> bool {
        match (self.samples.front(), self.samples.back()) {
            (Some(a), Some(b)) => b.at.duration_since(a.at) >= WINDOW - SAMPLE_EVERY,
            _ => false,
        }
    }

    pub fn averages(&self) -> Option<LoadAverages> {
        let (a, b) = (self.samples.front()?, self.samples.back()?);
        let dt = b.at.duration_since(a.at).as_secs_f64();
        if dt <= 0.0 {
            return None;
        }
        let cpu = b.cpu.saturating_sub(a.cpu).as_secs_f64() / dt / self.cores as f64 * 100.0;
        let tx = b.bytes.saturating_sub(a.bytes) as f64 / dt;
        let q = self.samples.iter().map(|s| s.queue_ms).sum::<f64>() / self.samples.len() as f64;
        Some(LoadAverages {
            cpu_pct: cpu.clamp(0.0, 100.0),
            tx_bps: tx,
            queue_ms: q,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cpu_time_is_monotonic_and_moves() {
        let a = process_cpu_time().expect("cpu time");
        let mut x = 0u64;
        let t = Instant::now();
        while t.elapsed() < Duration::from_millis(200) {
            x = x.wrapping_mul(6364136223846793005).wrapping_add(1);
        }
        std::hint::black_box(x);
        let b = process_cpu_time().unwrap();
        assert!(b > a, "busy loop must consume CPU time");
    }

    #[test]
    fn averages_over_window() {
        let mut s = LoadSampler::new(4);
        let t0 = Instant::now();
        for i in 0..=20u64 {
            // 2 s per sample; the process uses 1 core fully; 1 MB/s; queue 10 ms.
            s.record(
                t0 + Duration::from_secs(2 * i),
                Duration::from_secs(2 * i),
                2_000_000 * i,
                10.0,
            );
        }
        let a = s.averages().unwrap();
        assert!((a.cpu_pct - 25.0).abs() < 0.1, "{a:?}");
        assert!((a.tx_bps - 1_000_000.0).abs() < 1.0);
        assert!((a.queue_ms - 10.0).abs() < 1e-9);
        assert!((s.peak_mbps - 8.0).abs() < 0.2, "peak {}", s.peak_mbps);
        // Old samples leave the window.
        assert!(s.samples.len() <= 17);
    }
}
