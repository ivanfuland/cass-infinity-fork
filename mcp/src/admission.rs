//! The service-wide execution pool.
//!
//! One [`Admission`] is created once with the fixed startup values `P`
//! (`--max-concurrent`) and `Q` (`--max-queued`) and is shared by every SDK
//! session and all four tools. It owns two facts and nothing else:
//!
//! * at most `P` requests may hold an execution slot, including requests whose
//!   child is still being reaped, and
//! * at most `Q` requests may wait, in strict arrival order.
//!
//! Every decision happens under one mutex. A slot is handed straight from the
//! releasing request to the queue head, so a newly arriving request can never
//! take a slot that a waiting request is owed. The queue order is therefore
//! decided synchronously by [`Admission::enter`]; it is never inferred from
//! packet timing.

use std::collections::VecDeque;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};

use tokio::sync::oneshot;

/// The shared pool: `P` execution slots and `Q` waiting positions.
pub(crate) struct Admission {
    state: Mutex<State>,
    next_id: AtomicU64,
}

struct State {
    running: usize,
    max_running: usize,
    queue: VecDeque<Entry>,
    max_queued: usize,
}

struct Entry {
    id: u64,
    /// Whether this entry's slot was already handed over. Written and read only
    /// while `Admission::state` is held; it exists so a [`Waiter`] that is
    /// dropped after the hand-over can tell "the slot is mine" from "the
    /// receiver had already vanished and the slot went back to the pool".
    granted: Arc<AtomicBool>,
    /// Delivers the hand-over. Dropped, never sent, when the waiter leaves the
    /// queue on its own.
    grant: oneshot::Sender<Slot>,
}

/// Evidence that one execution slot was handed to the waiter that received it.
struct Slot;

/// What one [`Admission::enter`] decided.
pub(crate) enum AdmissionOutcome {
    /// The caller now owns one execution slot.
    Running(Permit),
    /// The request is registered in the waiting queue, in this position.
    Queued(Waiter),
    /// The slots and the waiting queue are both full.
    Busy,
}

/// One execution slot. It is released exactly once, when it is dropped; it
/// cannot be copied or duplicated.
pub(crate) struct Permit {
    admission: Arc<Admission>,
}

/// One registered waiting position. It is granted a [`Permit`] when a slot
/// reaches it at the head of the queue.
pub(crate) struct Waiter {
    admission: Arc<Admission>,
    id: u64,
    granted: Arc<AtomicBool>,
    grant: Option<oneshot::Receiver<Slot>>,
    claimed: bool,
}

impl Admission {
    /// Build the one pool for a service. Both values are already validated as
    /// strictly positive startup options; no default lives here.
    pub(crate) fn new(max_running: usize, max_queued: usize) -> Arc<Self> {
        debug_assert!(max_running > 0 && max_queued > 0);
        Arc::new(Self {
            state: Mutex::new(State {
                running: 0,
                max_running,
                queue: VecDeque::new(),
                max_queued,
            }),
            next_id: AtomicU64::new(1),
        })
    }

    /// Register one request, atomically, in a single observation of the state.
    ///
    /// A slot is taken only when one is free *and* nobody is waiting: a new
    /// request never consumes a slot that the queue head is owed. Otherwise a
    /// strictly positive queue position is registered, or the request is
    /// refused.
    pub(crate) fn enter(self: &Arc<Self>) -> AdmissionOutcome {
        let mut state = self.lock();
        if state.running < state.max_running && state.queue.is_empty() {
            state.running += 1;
            return AdmissionOutcome::Running(Permit {
                admission: Arc::clone(self),
            });
        }
        if state.queue.len() < state.max_queued {
            let id = self.next_id.fetch_add(1, Ordering::Relaxed);
            let (grant, receiver) = oneshot::channel();
            let granted = Arc::new(AtomicBool::new(false));
            state.queue.push_back(Entry {
                id,
                granted: Arc::clone(&granted),
                grant,
            });
            return AdmissionOutcome::Queued(Waiter {
                admission: Arc::clone(self),
                id,
                granted,
                grant: Some(receiver),
                claimed: false,
            });
        }
        AdmissionOutcome::Busy
    }

    fn lock(&self) -> MutexGuard<'_, State> {
        // A poisoned lock only means some other task panicked while holding it;
        // the counters are still consistent, so keep using them.
        self.state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    /// Give one slot back. It goes to the queue head if anyone is waiting, and
    /// the caller's slot count drops only when no waiter remains.
    fn release_slot(&self) {
        let mut state = self.lock();
        Self::release_locked(&mut state);
    }

    fn release_locked(state: &mut State) {
        // The hand-over is a value move plus a task wake: the receiver is never
        // polled inline, so no code re-enters this admission, and nothing with
        // a drop callback is dropped here.
        while let Some(entry) = state.queue.pop_front() {
            entry.granted.store(true, Ordering::Relaxed);
            match entry.grant.send(Slot) {
                // The slot moved to that waiter and still counts as running
                // until that waiter releases it.
                Ok(()) => return,
                // The receiver vanished; the slot stays here and goes to the
                // next waiter, so a dead waiter can never strand a slot.
                Err(_) => entry.granted.store(false, Ordering::Relaxed),
            }
        }
        debug_assert!(state.running > 0, "a permit was released without a slot");
        state.running = state.running.saturating_sub(1);
    }

    #[cfg(test)]
    pub(crate) fn counters(&self) -> (usize, usize) {
        let state = self.lock();
        (state.running, state.queue.len())
    }
}

impl Drop for Permit {
    fn drop(&mut self) {
        self.admission.release_slot();
    }
}

impl std::fmt::Debug for Admission {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let state = self.lock();
        formatter
            .debug_struct("Admission")
            .field("running", &state.running)
            .field("max_running", &state.max_running)
            .field("queued", &state.queue.len())
            .field("max_queued", &state.max_queued)
            .finish()
    }
}

impl Waiter {
    /// Wait for this position to be granted a slot.
    ///
    /// Dropping the returned future before it completes is legal and is exactly
    /// what a dropped request future does: the queue entry is removed, or the
    /// already-handed-over slot is returned to the pool so the queue advances.
    pub(crate) async fn wait(mut self) -> Permit {
        let grant = self.grant.take().expect("a waiter is claimed exactly once");
        match grant.await {
            Ok(Slot) => {
                self.claimed = true;
                Permit {
                    admission: Arc::clone(&self.admission),
                }
            }
            // The sender only disappears when the whole pool is dropped, and
            // this waiter keeps it alive. Be total rather than panic.
            Err(_) => Permit {
                admission: Arc::clone(&self.admission),
            },
        }
    }
}

impl Drop for Waiter {
    fn drop(&mut self) {
        if self.claimed {
            // The permit owns the slot now.
            return;
        }
        let mut state = self.admission.lock();
        if let Some(index) = state.queue.iter().position(|entry| entry.id == self.id) {
            // Still waiting: drop the position and let later requests use it.
            state.queue.remove(index);
            return;
        }
        if self.granted.load(Ordering::Relaxed) {
            // Granted but never claimed: return the slot, which advances the
            // queue or lowers the count exactly once.
            Admission::release_locked(&mut state);
        }
        // Otherwise the slot was already reclaimed by `release_locked` when it
        // found this waiter's receiver gone; there is nothing left to return.
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::future::Future;
    use std::pin::Pin;
    use std::sync::atomic::AtomicUsize;
    use std::task::{Context, Poll, Waker};
    use std::time::Duration;

    fn running(outcome: AdmissionOutcome) -> Permit {
        match outcome {
            AdmissionOutcome::Running(permit) => permit,
            AdmissionOutcome::Queued(_) => {
                panic!("expected an execution slot, got a queue position")
            }
            AdmissionOutcome::Busy => panic!("expected an execution slot, got a refusal"),
        }
    }

    fn queued(outcome: AdmissionOutcome) -> Waiter {
        match outcome {
            AdmissionOutcome::Queued(waiter) => waiter,
            AdmissionOutcome::Running(_) => panic!("expected a queue position, got a slot"),
            AdmissionOutcome::Busy => panic!("expected a queue position, got a refusal"),
        }
    }

    fn assert_busy(outcome: AdmissionOutcome) {
        assert!(
            matches!(outcome, AdmissionOutcome::Busy),
            "expected the fixed busy decision"
        );
    }

    /// Poll once with a waker that does nothing. Every step of this protocol is
    /// decided under the state lock, so a single poll is enough to observe
    /// "pending" or "ready" without sleeping or guessing.
    fn poll_once<F: Future>(future: Pin<&mut F>) -> Poll<F::Output> {
        let waker = Waker::noop();
        let mut context = Context::from_waker(waker);
        future.poll(&mut context)
    }

    #[tokio::test]
    async fn enter_fills_slots_then_registers_waiters_then_refuses() {
        let admission = Admission::new(2, 3);
        let first = running(admission.enter());
        let second = running(admission.enter());
        assert_eq!(admission.counters(), (2, 0));

        let mut waiters = Vec::new();
        for _ in 0..3 {
            waiters.push(queued(admission.enter()));
        }
        assert_eq!(
            admission.counters(),
            (2, 3),
            "Q positions are registered in order"
        );

        assert_busy(admission.enter());
        assert_eq!(
            admission.counters(),
            (2, 3),
            "a refusal must not add a queue position"
        );

        drop(first);
        drop(second);
        for waiter in waiters {
            drop(waiter.wait().await);
        }
        assert_eq!(admission.counters(), (0, 0));
        let last = running(admission.enter());
        drop(last);
        assert_eq!(admission.counters(), (0, 0));
    }

    #[tokio::test]
    async fn a_release_advances_only_the_head_and_a_new_request_cannot_jump_it() {
        let admission = Admission::new(1, 2);
        let permit = running(admission.enter());
        let head = queued(admission.enter());
        let second = queued(admission.enter());
        assert_eq!(admission.counters(), (1, 2));

        drop(permit);
        assert_eq!(
            admission.counters(),
            (1, 1),
            "the hand-over leaves the queue but keeps the slot"
        );

        // The freshly released slot belongs to the head; a new request must not
        // take it and must not overtake anybody.
        let late = queued(admission.enter());
        assert_eq!(admission.counters(), (1, 2));

        let permit = head.wait().await;
        assert_eq!(admission.counters(), (1, 2), "the head claims its slot");
        drop(permit);
        assert_eq!(admission.counters(), (1, 1));

        let permit = second.wait().await;
        drop(permit);
        assert_eq!(admission.counters(), (1, 0));
        let permit = late.wait().await;
        drop(permit);
        assert_eq!(admission.counters(), (0, 0));
    }

    #[tokio::test]
    async fn a_waiter_is_pending_until_its_turn_and_ready_after_the_hand_over() {
        let admission = Admission::new(1, 1);
        let permit = running(admission.enter());
        let waiter = queued(admission.enter());
        let mut waiting = Box::pin(waiter.wait());
        assert!(
            poll_once(waiting.as_mut()).is_pending(),
            "a queued waiter has no slot yet"
        );

        drop(permit);
        let permit = match poll_once(waiting.as_mut()) {
            Poll::Ready(permit) => permit,
            Poll::Pending => panic!("the head must be granted as soon as a slot is released"),
        };
        assert_eq!(admission.counters(), (1, 0));
        drop(permit);
        assert_eq!(admission.counters(), (0, 0));
    }

    #[tokio::test]
    async fn dropping_a_waiting_waiter_frees_only_its_queue_position() {
        let admission = Admission::new(1, 2);
        let permit = running(admission.enter());
        let head = queued(admission.enter());
        let tail = queued(admission.enter());
        assert_eq!(admission.counters(), (1, 2));

        drop(head);
        assert_eq!(
            admission.counters(),
            (1, 1),
            "a dropped waiting request returns its queue position and nothing else"
        );

        drop(permit);
        assert_eq!(
            admission.counters(),
            (1, 0),
            "the dropped request is not owed a slot"
        );
        let permit = tail.wait().await;
        drop(permit);
        assert_eq!(admission.counters(), (0, 0));
    }

    #[tokio::test]
    async fn dropping_a_granted_but_unclaimed_waiter_returns_the_slot_to_the_next() {
        let admission = Admission::new(1, 2);
        let permit = running(admission.enter());
        let first = queued(admission.enter());
        let second = queued(admission.enter());

        drop(permit);
        assert_eq!(admission.counters(), (1, 1));
        drop(first);
        assert_eq!(
            admission.counters(),
            (1, 0),
            "the unclaimed hand-over returns exactly one slot"
        );

        let permit = second.wait().await;
        assert_eq!(admission.counters(), (1, 0));
        drop(permit);
        assert_eq!(admission.counters(), (0, 0));
    }

    #[tokio::test]
    async fn a_middle_waiter_can_leave_without_disturbing_the_order() {
        let admission = Admission::new(1, 3);
        let permit = running(admission.enter());
        let first = queued(admission.enter());
        let middle = queued(admission.enter());
        let last = queued(admission.enter());
        assert_eq!(admission.counters(), (1, 3));

        drop(middle);
        assert_eq!(admission.counters(), (1, 2));

        drop(permit);
        assert_eq!(admission.counters(), (1, 1));
        let permit = first.wait().await;
        drop(permit);
        assert_eq!(
            admission.counters(),
            (1, 0),
            "the slot must pass over the departed middle request to the tail"
        );
        let permit = last.wait().await;
        drop(permit);
        assert_eq!(admission.counters(), (0, 0));
    }

    #[tokio::test]
    async fn a_hand_over_whose_receiver_vanished_does_not_strand_the_slot() {
        let admission = Admission::new(1, 1);
        let permit = running(admission.enter());
        let mut waiter = queued(admission.enter());
        assert_eq!(admission.counters(), (1, 1));

        // Simulate a task that disappears between registration and hand-over:
        // the receiver is dropped while the queue entry is still in place. The
        // waiter is leaked so only the pool can recover the slot.
        let receiver = waiter.grant.take().expect("pending receiver");
        drop(receiver);
        std::mem::forget(waiter);

        drop(permit);
        assert_eq!(
            admission.counters(),
            (0, 0),
            "a hand-over with no receiver must return the slot to the pool"
        );
        drop(running(admission.enter()));
        assert_eq!(admission.counters(), (0, 0));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn concurrent_enter_and_release_never_double_frees_or_deadlocks() {
        const SLOTS: usize = 3;
        const QUEUE: usize = 6;
        const CALLERS: usize = 48;

        let admission = Admission::new(SLOTS, QUEUE);
        let live = Arc::new(AtomicUsize::new(0));
        let tasks: Vec<_> = (0..CALLERS)
            .map(|_| {
                let admission = Arc::clone(&admission);
                let live = Arc::clone(&live);
                tokio::spawn(async move {
                    let permit = match admission.enter() {
                        AdmissionOutcome::Running(permit) => permit,
                        AdmissionOutcome::Queued(waiter) => waiter.wait().await,
                        AdmissionOutcome::Busy => return false,
                    };
                    let now = live.fetch_add(1, Ordering::SeqCst) + 1;
                    assert!(now <= SLOTS, "{now} holders exceeds the {SLOTS} slots");
                    tokio::task::yield_now().await;
                    live.fetch_sub(1, Ordering::SeqCst);
                    drop(permit);
                    true
                })
            })
            .collect();

        let admitted = tokio::time::timeout(Duration::from_secs(30), async {
            let mut admitted = 0;
            for task in tasks {
                if task.await.expect("caller task") {
                    admitted += 1;
                }
            }
            admitted
        })
        .await
        .expect("the pool must not deadlock");

        assert!(admitted >= SLOTS, "the pool must keep admitting work");
        assert_eq!(
            admission.counters(),
            (0, 0),
            "no slot and no queue position may leak"
        );
    }
}
