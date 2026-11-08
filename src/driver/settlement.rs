//! Prove to a restarted gateway that no accepted lifecycle operation remains.
//!
//! The gateway claims each create/start before dispatching it. A gateway that
//! exits mid-call never learns the outcome, and its claim would block stop,
//! start and delete forever. This adapter owns every lifecycle operation past
//! RPC cancellation, so it can answer: once the operations accepted for a
//! sandbox have finished, none can change its resources any more.

use super::*;
use std::sync::Mutex as StdMutex;
use tokio::sync::Notify;

/// Lifecycle operations accepted per sandbox and not yet finished.
///
/// A ticket is taken synchronously when the RPC handler starts, before any
/// await, and lives in the owned task until its work and compensation end.
#[derive(Default)]
pub(super) struct InFlight {
    counts: StdMutex<BTreeMap<String, usize>>,
    finished: Notify,
}

pub(super) struct Ticket {
    registry: Arc<InFlight>,
    id: String,
}

impl InFlight {
    pub(super) fn enter(self: &Arc<Self>, id: &str) -> Ticket {
        *self
            .counts
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .entry(id.to_owned())
            .or_default() += 1;
        Ticket {
            registry: self.clone(),
            id: id.to_owned(),
        }
    }

    fn busy(&self, id: &str) -> bool {
        self.counts
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .contains_key(id)
    }

    /// Wait until every operation accepted for `id` so far has finished.
    pub(super) async fn wait_idle(&self, id: &str) {
        loop {
            // Register for the wakeup before checking, so a ticket finishing
            // in between cannot be missed.
            let finished = self.finished.notified();
            tokio::pin!(finished);
            finished.as_mut().enable();
            if !self.busy(id) {
                return;
            }
            finished.await;
        }
    }
}

impl Drop for Ticket {
    fn drop(&mut self) {
        {
            let mut counts = self
                .registry
                .counts
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if let Some(count) = counts.get_mut(&self.id) {
                *count -= 1;
                if *count == 0 {
                    counts.remove(&self.id);
                }
            }
        }
        self.registry.finished.notify_waiters();
    }
}

impl Driver {
    pub(super) async fn settle_sandbox_operations_owned(
        &self,
        request: Request<c::SettleSandboxOperationsRequest>,
    ) -> Result<Response<c::SettleSandboxOperationsResponse>, Status> {
        let id = request.into_inner().sandbox_id;
        self.in_flight.wait_idle(&id).await;
        // Adapter recovery and any work already holding the sandbox's
        // lifecycle lock finish before this returns.
        let _recovery = self.recovery_gate.read().await;
        if let Ok(validated) = SandboxId::parse(&id) {
            let _guard = self.lifecycle.lock(validated.as_str()).await?;
        }
        Ok(Response::new(c::SettleSandboxOperationsResponse {}))
    }
}

#[tonic::async_trait]
impl c::compute_driver_operation_settlement_server::ComputeDriverOperationSettlement for Driver {
    async fn settle_sandbox_operations(
        &self,
        request: Request<c::SettleSandboxOperationsRequest>,
    ) -> Result<Response<c::SettleSandboxOperationsResponse>, Status> {
        self.settle_sandbox_operations_owned(request).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn settlement_waits_for_accepted_operations_only() {
        let in_flight = Arc::new(InFlight::default());
        // Nothing accepted: settled at once.
        tokio::time::timeout(Duration::from_secs(1), in_flight.wait_idle("a"))
            .await
            .expect("idle sandbox settles immediately");

        let first = in_flight.enter("a");
        let second = in_flight.enter("a");
        let other = in_flight.enter("b");
        let waiter = tokio::spawn({
            let in_flight = in_flight.clone();
            async move { in_flight.wait_idle("a").await }
        });
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert!(!waiter.is_finished(), "two operations still running");
        drop(first);
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert!(!waiter.is_finished(), "one operation still running");
        drop(second);
        tokio::time::timeout(Duration::from_secs(1), waiter)
            .await
            .expect("settles once both finish")
            .expect("waiter task");
        // Another sandbox's operation never delays this one.
        drop(other);
    }
}
