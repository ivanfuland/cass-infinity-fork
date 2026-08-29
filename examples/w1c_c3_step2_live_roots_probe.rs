//! Drill asset (plan v6 Stage C, Task C3 Step 2) — not a product feature, not
//! wired into the `cass` command surface or `Commands` enum.
//!
//! Read-only enumeration of this machine's real (non-staging) connector
//! default roots, via `franken_agent_detection::detect_installed_agents`
//! (the same detection primitive `cass onboarding` uses at
//! src/lib.rs:70503-70512). This is the authoritative source for the
//! "live-roots" scan-root set the plan's C3 Step 2 command needs
//! (`live-roots.args`): the real machine's home has grown since the
//! raw-mirror snapshot was captured, and `cass ingest manifest` takes
//! explicit `--scan-root` args per connector rather than doing its own
//! default-root detection (src/ingest_manifest.rs uses
//! `ScanContext::with_roots`, never `local_default`) -- so the manifest's
//! scan roots must be assembled by the caller, not left to connector
//! defaults.
//!
//! Must run with the real `$HOME` in effect (before any fake-HOME override
//! for the staging mirror pass) -- this probe performs zero writes and
//! zero mutation of any cass state; it only calls each connector's
//! `detect()` and reports `root_paths`.

use franken_agent_detection::{AgentDetectOptions, detect_installed_agents};

fn main() {
    let opts = AgentDetectOptions {
        only_connectors: None,
        include_undetected: true,
        root_overrides: Vec::new(),
    };

    let report = detect_installed_agents(&opts).expect("detect_installed_agents");

    println!("{}", serde_json::to_string_pretty(&report).unwrap());

    eprintln!(
        "\n[w1c_c3_step2_live_roots_probe] detected={}/{} (see summary above for full report)",
        report.summary.detected_count, report.summary.total_count
    );
}
