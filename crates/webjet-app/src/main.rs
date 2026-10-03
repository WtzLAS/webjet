//! webjet-app: shows a Webjet network through the agent on this machine.
//!
//!   webjet-app [--socket <control socket>] [--keys <account key dir>]
//!
//! Defaults match `webjetctl`: `WEBJET_SOCKET` / the platform's control
//! socket, and `WEBJET_KEYS` / `~/.config/webjet/accounts`.

use std::path::PathBuf;
use std::sync::Arc;

fn arg(args: &[String], name: &str) -> Option<PathBuf> {
    args.iter()
        .position(|a| a == name)
        .and_then(|i| args.get(i + 1))
        .map(PathBuf::from)
}

fn main() -> anyhow::Result<()> {
    let args: Vec<String> = std::env::args().collect();
    if args.iter().any(|a| a == "-h" || a == "--help") {
        println!("usage: webjet-app [--socket <path>] [--keys <dir>]");
        return Ok(());
    }
    let socket = arg(&args, "--socket").unwrap_or_else(webjet_app::client::default_socket);
    let keys = arg(&args, "--keys").unwrap_or_else(webjet_app::client::default_keys);
    // The control channel and signing run on tokio; GPUI owns the main thread.
    let rt = Arc::new(
        tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()?,
    );
    gpui::Application::new().run(move |cx| {
        cx.on_window_closed(|cx| {
            if cx.windows().is_empty() {
                cx.quit();
            }
        })
        .detach();
        if let Err(e) = webjet_app::ui::open(cx, rt, socket, keys) {
            eprintln!("webjet-app: {e:#}");
            std::process::exit(1);
        }
    });
    Ok(())
}
