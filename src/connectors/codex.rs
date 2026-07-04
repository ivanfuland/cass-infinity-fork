use anyhow::Result;

use super::{Connector, DetectionResult, DiscoveredSourceFile, NormalizedConversation, ScanContext};

/// Thin wrapper over the upstream franken Codex connector.
///
/// Historically this wrapped `inner.scan()` with `augment_modern_codex_messages`
/// to recover modern `output_text` assistant blocks and `function_call` tool
/// calls that franken <=0.1.8 dropped. franken 0.1.9 (issue #13 / commit 6d75cff)
/// parses those natively, so the augmentation was removed and this is now a
/// straight delegation.
pub struct CodexConnector {
    inner: franken_agent_detection::CodexConnector,
}

impl Default for CodexConnector {
    fn default() -> Self {
        Self::new()
    }
}

impl CodexConnector {
    #[must_use]
    pub fn new() -> Self {
        Self {
            inner: franken_agent_detection::CodexConnector::new(),
        }
    }
}

impl Connector for CodexConnector {
    fn detect(&self) -> DetectionResult {
        self.inner.detect()
    }

    fn scan(&self, ctx: &ScanContext) -> Result<Vec<NormalizedConversation>> {
        self.inner.scan(ctx)
    }

    fn supports_streaming_scan(&self) -> bool {
        self.inner.supports_streaming_scan()
    }

    fn discover_source_files(&self, ctx: &ScanContext) -> Result<Vec<DiscoveredSourceFile>> {
        self.inner.discover_source_files(ctx)
    }

    fn scan_with_callback(
        &self,
        ctx: &ScanContext,
        on_conversation: &mut dyn FnMut(NormalizedConversation) -> Result<()>,
    ) -> Result<()> {
        self.inner.scan_with_callback(ctx, on_conversation)
    }
}
