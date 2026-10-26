//! Bounded retry ownership, separate from the watcher and reconciliation loop.

use crate::event::AuditEvent;

type Error = Box<dyn std::error::Error>;

pub struct HistoryQueue {
    output: crate::presentation::Options,
    pending: Vec<AuditEvent>,
    pending_bytes: usize,
    max_events: usize,
    max_bytes: usize,
}

impl HistoryQueue {
    pub fn with_output(output: crate::presentation::Options) -> Self {
        Self {
            output,
            ..Self::new()
        }
    }
    pub fn new() -> Self {
        Self::with_limits(4096, 16 * 1024 * 1024)
    }

    fn with_limits(max_events: usize, max_bytes: usize) -> Self {
        Self {
            output: crate::presentation::Options::detect(crate::presentation::Mode::Legacy, true),
            pending: Vec::new(),
            pending_bytes: 0,
            max_events,
            max_bytes,
        }
    }

    pub fn record(
        &mut self,
        events: &[AuditEvent],
        mut append: impl FnMut(&[AuditEvent]) -> Result<(), Error>,
    ) -> Result<(), Error> {
        if !self.pending.is_empty() {
            match append(&self.pending) {
                Ok(()) => {
                    self.pending = Vec::new();
                    self.pending_bytes = 0;
                }
                Err(error) => self.output.diagnostic("fim", "warning", &format!(
                    "History write failed; monitoring continues and will retry {} pending event(s): {error}", self.pending.len()
                ))?,
            }
        }
        if events.is_empty() {
            return Ok(());
        }
        if self.pending.is_empty() {
            // Healthy writes need no retry buffer, even for a large scan.
            match append(events) {
                Ok(()) => return Ok(()),
                Err(error) => self.output.diagnostic(
                    "fim",
                    "warning",
                    &format!("History write failed: {error}"),
                )?,
            }
        }
        let mut bytes = ByteCount(self.pending_bytes);
        for event in events {
            serde_json::to_writer(&mut bytes, event)?;
            bytes.0 = bytes.0.saturating_add(1);
        }
        let count = self.pending.len().saturating_add(events.len());
        if count > self.max_events || bytes.0 > self.max_bytes {
            return Err(format!(
                "History backlog limit exceeded ({count} events, {} bytes; limits: {} events / {} bytes); monitoring stopped because evidence could not be persisted",
                bytes.0, self.max_events, self.max_bytes
            ).into());
        }
        self.pending.extend_from_slice(events);
        self.pending_bytes = bytes.0;
        self.output.diagnostic(
            "fim",
            "warning",
            &format!("History write pending; monitoring continues with {count} buffered event(s)"),
        )?;
        Ok(())
    }
}

struct ByteCount(usize);

impl std::io::Write for ByteCount {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.0 = self.0.saturating_add(bytes.len());
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn event(sequence: u64) -> AuditEvent {
        serde_json::from_value(serde_json::json!({
            "schema_version": 1, "root_hex": "2f", "run_id": "run",
            "sequence": sequence, "origin": "RECONCILIATION", "kind": "CREATED",
            "detected_at": "2026-01-01T00:00:00.000000000Z",
            "baseline_status": "ADDED", "changed_fields": [],
            "current_path": {"display": "a", "hex": "61"}, "previous_path": null,
            "before": null, "after": null, "baseline": null, "content_changed": null,
            "replaced": false, "replaced_before": null
        }))
        .unwrap()
    }

    #[test]
    fn stops_before_a_failed_backlog_exceeds_count_or_bytes() {
        for (count, bytes) in [(1, usize::MAX), (100, 1)] {
            let mut queue = HistoryQueue::with_limits(count, bytes);
            let result = queue.record(&[event(1), event(2)], |_| Err("disk unavailable".into()));
            assert!(
                result.is_err(),
                "an overflowing failed backlog must stop monitoring"
            );
            assert!(queue.pending.len() <= count);
        }
    }

    #[test]
    fn retries_without_dropping_events_and_releases_memory_after_recovery() {
        let mut queue = HistoryQueue::with_limits(2, 8192);
        queue
            .record(&[event(1)], |_| Err("disk unavailable".into()))
            .unwrap();
        assert_eq!(queue.pending.len(), 1);
        let mut written = Vec::new();
        queue
            .record(&[event(2)], |events| {
                written.extend(events.iter().map(|event| event.sequence));
                Ok(())
            })
            .unwrap();
        assert_eq!(written, [1, 2]);
        assert!(queue.pending.is_empty());
    }

    #[test]
    fn successful_large_batches_do_not_require_a_retry_backlog() {
        let mut queue = HistoryQueue::with_limits(1, 1);
        queue.record(&[event(1), event(2)], |_| Ok(())).unwrap();
        assert!(queue.pending.is_empty());
    }
}
