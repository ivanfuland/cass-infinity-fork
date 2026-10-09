//! Input-phase types shared by the later regression runners.

use std::path::PathBuf;
use std::sync::Arc;

use clap::{Args, Subcommand, ValueEnum};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::search::regression_binding::InputBinding;
use crate::search::regression_io::RegressionIoContext;

#[derive(Clone, Debug, Args)]
pub struct InputOptions {
    #[arg(long)]
    pub suite: PathBuf,
    #[arg(long)]
    pub suite_sha256: String,
    #[arg(long)]
    pub labels: PathBuf,
    #[arg(long)]
    pub labels_sha256: String,
    #[command(flatten)]
    pub output: OutputOptions,
}

#[derive(Clone, Debug, Args)]
pub struct OutputOptions {
    #[arg(long)]
    pub output_root: PathBuf,
    #[arg(long)]
    pub run_id: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, ValueEnum)]
pub enum RerankSwitch {
    Off,
    On,
}

#[derive(Clone, Debug, Subcommand)]
pub enum RegressionCommand {
    /// Validate pinned inputs. Search execution is a later stage.
    FullSearch {
        #[command(flatten)]
        input: InputOptions,
        #[arg(long)]
        database: PathBuf,
        #[arg(long)]
        expected_binding: PathBuf,
        #[arg(long)]
        expected_binding_sha256: String,
        #[arg(long)]
        source_manifest: PathBuf,
        #[arg(long)]
        source_producer_receipt: PathBuf,
        #[arg(long)]
        source_producer_receipt_sha256: String,
        #[arg(long, value_enum)]
        search_mode: crate::search::query::SearchMode,
        #[arg(long, value_enum)]
        vector_search_mode: Option<crate::search::query::VectorSearchMode>,
        #[arg(long, value_parser = clap::value_parser!(u32).range(1..))]
        rrf_limit: u32,
        #[arg(long, value_enum)]
        rerank: RerankSwitch,
        #[arg(long, value_parser = clap::value_parser!(u32).range(1..))]
        page_size: Option<u32>,
        #[arg(long, value_enum)]
        rerank_provider: Option<crate::search::rerank::types::ProviderChoice>,
        #[arg(long, value_delimiter = ',', default_value = "5,10,20")]
        cutoffs: Vec<u32>,
    },
    /// Validate the frozen package. Reranking is a later stage.
    FixedCandidate {
        #[command(flatten)]
        input: InputOptions,
        #[arg(long)]
        pool_binding: PathBuf,
        #[arg(long)]
        pool_binding_sha256: String,
        #[arg(long, value_enum)]
        rerank_provider: crate::search::rerank::types::ProviderChoice,
        #[arg(long, value_delimiter = ',', default_value = "5,10,20")]
        cutoffs: Vec<u32>,
    },
    /// Validate pinned comparison files. Evaluation is a later stage.
    Compare {
        #[arg(long)]
        left: PathBuf,
        #[arg(long)]
        left_sha256: String,
        #[arg(long)]
        right: PathBuf,
        #[arg(long)]
        right_sha256: String,
        #[arg(long)]
        labels: PathBuf,
        #[arg(long)]
        labels_sha256: String,
        #[command(flatten)]
        output: OutputOptions,
        #[arg(long, value_delimiter = ',', default_value = "5,10,20")]
        cutoffs: Vec<u32>,
    },
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, Deserialize, Serialize)]
#[serde(untagged)]
pub(crate) enum MessageId {
    Integer(i64),
    Text(String),
}

#[derive(Clone, Debug, Deserialize)]
pub(crate) struct Asset {
    pub(crate) source_path: String,
    pub(crate) path: String,
    pub(crate) sha256: String,
    pub(crate) bytes: u64,
    pub(crate) roles: Vec<String>,
}

#[derive(Clone, Debug, Deserialize)]
pub(crate) struct InputSlot {
    pub(crate) rank: usize,
    pub(crate) message_id: MessageId,
    pub(crate) conversation_id: Value,
    pub(crate) text_sha256: String,
    pub(crate) bytes: u64,
    pub(crate) source_sha256: String,
    pub(crate) original_score: Value,
    pub(crate) text_path: String,
    pub(crate) scoreable: bool,
    pub(crate) fallback_reason: Value,
}

#[derive(Clone, Debug, Deserialize)]
pub(crate) struct InputWindow {
    pub(crate) qid: String,
    pub(crate) query: String,
    pub(crate) query_sha256: String,
    pub(crate) items: Vec<InputSlot>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub(crate) struct LabelRecord {
    pub(crate) key: LabelKey,
    pub(crate) value: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize)]
pub(crate) struct LabelKey {
    pub(crate) query_sha256: String,
    pub(crate) label_text_sha256: String,
    pub(crate) label_policy_sha256: String,
}

/// No canonical-object hash replaces an externally verified file hash.
pub(crate) struct ValidatedInputs {
    pub(crate) suite_root: PathBuf,
    pub(crate) suite_sha256: String,
    pub(crate) source_inventory_sha256: String,
    pub(crate) input_manifest_sha256: String,
    pub(crate) windows_file_sha256: String,
    pub(crate) labels_sha256: String,
    pub(crate) label_freeze_sha256: String,
    pub(crate) label_policy_sha256: String,
    pub(crate) windows: Vec<InputWindow>,
    pub(crate) labels: Vec<LabelRecord>,
    pub(crate) assets: Vec<Asset>,
    pub(crate) not_user_confirmed: bool,
    pub(crate) not_an_independent_test_set: bool,
}

#[derive(Clone, Debug)]
#[expect(
    dead_code,
    reason = "Later runners consume private cache, temporary and trace paths"
)]
pub(crate) struct RunPaths {
    pub(crate) run_root: PathBuf,
    pub(crate) cache_root: PathBuf,
    pub(crate) temp_root: PathBuf,
    pub(crate) trace_root: PathBuf,
    pub(crate) input_report: PathBuf,
}

/// Retains the readonly connection and its shared maintenance lease.
pub(crate) struct ValidatedRun {
    pub(crate) inputs: ValidatedInputs,
    pub(crate) paths: RunPaths,
    pub(crate) context: Option<Arc<RegressionIoContext>>,
    pub(crate) expected_binding: Option<InputBinding>,
    pub(crate) expected_binding_file_sha256: Option<String>,
    pub(crate) source_manifest: Option<PathBuf>,
    pub(crate) source_receipt_sha256: Option<String>,
}
