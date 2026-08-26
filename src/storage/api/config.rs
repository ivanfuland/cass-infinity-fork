//! Connection profiles and open options for storage::api.
//!
//! Stage A only defined the shapes; Stage B Task B2 (`backend_sqlite.rs`) adds
//! the PRAGMA target table below plus the actual application + readback
//! self-check (spec R0-B07 / R4-B1). The franken backend (Stage A) does not
//! branch on `Profile`.

use std::time::Duration;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Profile {
    Production,
    BulkRebuild,
    ReadOnly,
    Memory,
}

/// Options for [`super::Conn::open_read_with`].
#[derive(Debug, Clone, Copy)]
pub struct OpenOptions {
    pub busy_timeout: Duration,
}

/// w1b Task B3 (D2, plan @783-786): statement-level `Busy{Statement}` bounded
/// retry parameters. "Conservative starting point" per spec -- these are
/// deliberately generous rather than aggressive; changing them is a recorded
/// decision (plan @786), not a tuning knob to adjust casually.
pub(crate) const STATEMENT_RETRY_MAX_ATTEMPTS: u32 = 5;
pub(crate) const STATEMENT_RETRY_BASE_MS: u64 = 50;
pub(crate) const STATEMENT_RETRY_TOTAL_CAP_MS: u64 = 1000;

/// w1b Task B3 (D2, plan @775-781): `with_tx`'s whole-transaction replay on
/// `Busy{Snapshot}` -- only for the `Fn` (pure, re-invocable) closure variant.
/// `with_tx_no_replay` never uses these.
pub(crate) const TX_REPLAY_MAX_ATTEMPTS: u32 = 3;
pub(crate) const TX_REPLAY_BASE_MS: u64 = 100;

/// w1b Task B3: both retry families use base*2^attempt with this symmetric
/// jitter band (plan's "±25% 抖动") to avoid lock-step retry storms across
/// threads that hit the same contention at the same moment.
pub(crate) const RETRY_JITTER_MIN_PERCENT: u64 = 75;
pub(crate) const RETRY_JITTER_MAX_PERCENT: u64 = 125;

/// w1b Task B2: env var that must be set to exactly `"1"` to unlock
/// `BulkRebuild`'s non-durable `synchronous=NORMAL` PRAGMA (plan @698-703,
/// spec R2-F15 + R4-B1 collapse). `--full` alone must never imply it -- named
/// with `UNSAFE`/`NONDURABLE` on purpose as a loud, hard-to-typo-into escape
/// hatch, not a casual performance knob.
pub(crate) const BULK_REBUILD_UNSAFE_ENV: &str = "CASS_BULK_REBUILD_UNSAFE_NONDURABLE";

/// w1b Task B2: declarative PRAGMA targets for one [`Profile`] (plan
/// @690-696 table). Deliberately backend-agnostic (no rusqlite import) --
/// `backend_sqlite.rs` is the only thing that applies these and performs the
/// readback self-check; keeping the shape here means a future non-sqlite
/// backend could reuse the same declared targets without pulling in rusqlite.
#[derive(Debug, Clone, Copy)]
pub(crate) struct PragmaPlan {
    /// `None` means "not applicable for this profile" (the plan table's
    /// "不适用"/"只读打开" cells) -- the caller must not attempt to set or
    /// read back this PRAGMA for that profile.
    pub(crate) journal_mode: Option<&'static str>,
    /// SQLite's own `synchronous` integer encoding: 0=OFF, 1=NORMAL, 2=FULL,
    /// 3=EXTRA. `None` means not applicable (skip, like `journal_mode`).
    pub(crate) synchronous: Option<i64>,
    pub(crate) busy_timeout_ms: u64,
    /// Set only when `BulkRebuild` actually engaged its non-durable path
    /// this call (env var present) -- the caller must log this exactly once
    /// at open time (plan @702: "启用时打开连接即打一行显式警告日志"),
    /// bundled into the plan so the warning can't drift out of sync with
    /// the env-var check that decided `synchronous`.
    pub(crate) unsafe_nondurable_warning: Option<&'static str>,
}

impl Profile {
    /// Resolve this profile's PRAGMA targets. `BulkRebuild` reads
    /// [`BULK_REBUILD_UNSAFE_ENV`] itself: unset (or not exactly `"1"`), it
    /// silently downgrades to `Production`'s durable settings -- "every
    /// write connection is Production/FULL unless explicitly unlocked" is
    /// the documented default-safe behavior (plan @700-703), not a hidden
    /// footgun a caller has to remember to check for separately.
    pub(crate) fn pragma_plan(self) -> PragmaPlan {
        match self {
            Profile::Production => PragmaPlan {
                journal_mode: Some("WAL"),
                synchronous: Some(2),
                busy_timeout_ms: 5000,
                unsafe_nondurable_warning: None,
            },
            Profile::BulkRebuild => {
                if std::env::var(BULK_REBUILD_UNSAFE_ENV).as_deref() == Ok("1") {
                    PragmaPlan {
                        journal_mode: Some("WAL"),
                        synchronous: Some(1),
                        busy_timeout_ms: 5000,
                        unsafe_nondurable_warning: Some(
                            "[cass] WARNING: CASS_BULK_REBUILD_UNSAFE_NONDURABLE=1 -- opening \
                             BulkRebuild connection with synchronous=NORMAL (non-durable; a \
                             power loss before the next checkpoint can roll back transactions \
                             SQLite already reported as committed)",
                        ),
                    }
                } else {
                    PragmaPlan {
                        journal_mode: Some("WAL"),
                        synchronous: Some(2),
                        busy_timeout_ms: 5000,
                        unsafe_nondurable_warning: None,
                    }
                }
            }
            Profile::ReadOnly => PragmaPlan {
                journal_mode: None,
                synchronous: None,
                busy_timeout_ms: 5000,
                unsafe_nondurable_warning: None,
            },
            Profile::Memory => PragmaPlan {
                journal_mode: Some("MEMORY"),
                synchronous: None,
                busy_timeout_ms: 0,
                unsafe_nondurable_warning: None,
            },
        }
    }
}
