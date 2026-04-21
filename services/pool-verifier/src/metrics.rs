use axum::{Extension, http::StatusCode, response::IntoResponse};
use prometheus_client::encoding::EncodeLabelSet;
use prometheus_client::metrics::counter::Counter;
use prometheus_client::metrics::family::Family;
use prometheus_client::registry::Registry;
use std::sync::Arc;

/// Label set for verdict outcome counters.
#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
pub(crate) struct VerdictLabels {
    pub(crate) accepted: String,
    pub(crate) reason_code: String,
}

/// Label set for policy reload counters.
#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
pub(crate) struct PolicyReloadLabels {
    pub(crate) result: String,
}

/// Prometheus metric families for the pool-verifier.
#[allow(clippy::struct_field_names)] // `_total` suffix is Prometheus naming convention
pub(crate) struct VerifierMetrics {
    pub(crate) verdicts_total: Family<VerdictLabels, Counter>,
    pub(crate) templates_evaluated_total: Counter,
    pub(crate) policy_reloads_total: Family<PolicyReloadLabels, Counter>,
    /// Count of templates where the v2.0 Invariant Shield pass was
    /// reached but the sender omitted `raw_block_hex`. Separate from
    /// `verdicts_total` because the shield skip is not a verdict
    /// outcome; dashboards use this to measure Phase 1 rollout
    /// coverage of gateways that ship raw block bytes.
    pub(crate) shield_skipped_total: Counter,
}

impl VerifierMetrics {
    pub(crate) fn new_registered(registry: &mut Registry) -> Self {
        let m = Self {
            verdicts_total: Family::default(),
            templates_evaluated_total: Counter::default(),
            policy_reloads_total: Family::default(),
            shield_skipped_total: Counter::default(),
        };
        registry.register(
            "verifier_verdicts_total",
            "Total verdicts emitted by the verifier",
            m.verdicts_total.clone(),
        );
        registry.register(
            "verifier_templates_evaluated_total",
            "Total templates evaluated",
            m.templates_evaluated_total.clone(),
        );
        registry.register(
            "verifier_policy_reloads_total",
            "Total policy reload attempts",
            m.policy_reloads_total.clone(),
        );
        registry.register(
            "verifier_shield_skipped_total",
            "Templates that reached the v2.0 Invariant Shield but omitted raw_block_hex",
            m.shield_skipped_total.clone(),
        );
        m
    }
}

/// Shared metrics reference.
pub(crate) type SharedVerifierMetrics = Arc<VerifierMetrics>;

/// `GET /metrics` handler serving `OpenMetrics` text format.
pub(crate) async fn verifier_metrics_handler(
    Extension(registry): Extension<reservegrid_common::metrics::SharedRegistry>,
) -> impl IntoResponse {
    let (status, content_type, body) = reservegrid_common::metrics::render_metrics(&registry);
    (
        StatusCode::from_u16(status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR),
        [(axum::http::header::CONTENT_TYPE, content_type)],
        body,
    )
}
