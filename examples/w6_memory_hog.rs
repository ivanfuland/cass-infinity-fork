//! T14-3 / #122b-1 block B: `memory_gate.sh --selfcheck`'s process-tree
//! self-test fixture. Spawns itself as a CHILD process (`--role child`)
//! *before* allocating anything -- `Command::spawn` does fork+exec, a
//! fresh process image, so the child never inherits the parent's resident
//! pages the way a raw `fork()`-without-exec's copy-on-write pages would.
//! Parent and child then EACH allocate `--mib` MiB and touch every 4KiB
//! page with a non-zero byte (an all-zero `vec![0u8; n]` can be satisfied
//! from the kernel's shared zero page without ever becoming resident --
//! VmRSS would under-report), and both hold that allocation for
//! `--hold-ms` milliseconds so `memory_gate.sh`'s poller has a known
//! window to sample. This gives the selfcheck a tree where each individual
//! process stays well under `2 * --mib`, but the tree's summed RSS is
//! close to `2 * --mib` -- the "peak_tree must be the sum, not any single
//! process's peak" case block B's assertions exist to pin.
//!
//! Usage: `w6_memory_hog [--role parent|child] [--mib N] [--hold-ms N]`.
//! The parent prints `pid=<parent_pid>` and `child_pid=<child_pid>` to
//! stdout (flushed) before allocating, so a caller can read both pids
//! straight off the process's own stdout instead of guessing them.

use clap::{Parser, ValueEnum};
use std::io::Write;

#[derive(Parser, Debug)]
#[command(name = "w6_memory_hog")]
struct Cli {
    #[arg(long, value_enum, default_value = "parent")]
    role: Role,
    #[arg(long, default_value_t = 150)]
    mib: usize,
    #[arg(long, default_value_t = 1000)]
    hold_ms: u64,
}

#[derive(ValueEnum, Clone, Copy, Debug, PartialEq, Eq)]
enum Role {
    Parent,
    Child,
}

/// `--mib` MiB, with every 4KiB page written a non-zero byte so the
/// allocation is actually resident (VmRSS), not satisfied by the kernel's
/// shared zero page. `std::hint::black_box` on the write loop is load-
/// bearing, not decorative: without it, a release build's dead-store
/// elimination sees `buf[i] = 1` is never read back afterward (the vec is
/// held only for its side effect, then dropped) and removes the entire
/// write loop -- confirmed empirically (2026-09-11): the un-black-boxed
/// version left child RSS flat at ~2.3MiB baseline instead of growing to
/// `mib`, since nothing forced the pages to actually fault in.
fn touch_pages(mib: usize) -> Vec<u8> {
    const PAGE: usize = 4096;
    let len = mib * 1024 * 1024;
    let mut buf = vec![0u8; len];
    let mut i = 0;
    while i < len {
        buf[i] = 1;
        i += PAGE;
    }
    std::hint::black_box(&buf);
    buf
}

fn run_child(cli: &Cli) {
    let _buf = touch_pages(cli.mib);
    std::thread::sleep(std::time::Duration::from_millis(cli.hold_ms));
}

fn run_parent(cli: &Cli) {
    let exe = std::env::current_exe().expect("current_exe");
    let mut child = std::process::Command::new(&exe)
        .arg("--role")
        .arg("child")
        .arg("--mib")
        .arg(cli.mib.to_string())
        .arg("--hold-ms")
        .arg(cli.hold_ms.to_string())
        .spawn()
        .expect("spawn child hog process");
    let child_pid = child.id();
    let parent_pid = std::process::id();

    println!("pid={parent_pid}");
    println!("child_pid={child_pid}");
    std::io::stdout().flush().ok();

    let _buf = touch_pages(cli.mib);
    std::thread::sleep(std::time::Duration::from_millis(cli.hold_ms));

    let _ = child.wait();
}

fn main() {
    let cli = Cli::parse();
    match cli.role {
        Role::Child => run_child(&cli),
        Role::Parent => run_parent(&cli),
    }
}
