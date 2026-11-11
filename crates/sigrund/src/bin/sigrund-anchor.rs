//! Disposable, single-threaded anchor for an already running environment.
use std::{io, path::Path};

fn run() -> io::Result<()> {
    let args: Vec<_> = std::env::args_os().skip(1).collect();
    if args.len() == 1 && args[0] == "--help" {
        println!(
            "Usage: sigrund-anchor --socket /ABSOLUTE/RENDEZVOUS.anchor\nRun inside the existing destination, then register its host-visible PID.\nThis disposable process is held until revocation or daemon shutdown.\nThe anchor requires an unfiltered, single-threaded supported environment."
        );
        return Ok(());
    }
    if args.len() != 2 || args[0] != "--socket" || !Path::new(&args[1]).is_absolute() {
        return Err(io::Error::other(
            "expected --socket /ABSOLUTE/RENDEZVOUS.anchor",
        ));
    }
    sigrund::client::run_dedicated_anchor(Path::new(&args[1]))
}
fn main() {
    if let Err(error) = run() {
        eprintln!("sigrund-anchor: {error}");
        std::process::exit(1);
    }
}
