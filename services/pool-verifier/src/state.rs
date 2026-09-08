use anyhow::{Context, anyhow};
use rg_protocol::PROTOCOL_VERSION;
use tracing::{error, warn};

use pool_verifier::mempool_view::MempoolView;
use pool_verifier::policy::PolicyConfig;
use pool_verifier::second_chance::SecondChance;

#[derive(Debug, Clone)]
pub struct PolicyHolder {
    pub config: PolicyConfig,
    pub toml_text: String,
}

#[derive(Clone)]
pub struct AppState {
    pub policy: std::sync::Arc<std::sync::RwLock<PolicyHolder>>,

    /// Phase 2 mempool view. `None` when `[policy.mempool] enforce`
    /// is `false` (default); the shield then runs Phase 1 only.
    /// `Some(view)` when the polling task is wired at startup;
    /// `evaluate_dynamic_phase2` reads a snapshot per template and
    /// passes it straight to `check_invariant_shield_inner`.
    /// `check_invariant_shield_with_mempool` is a single-expression
    /// wrapper over that same inner function, called only from
    /// `tests/phase2_eval.rs`.
    pub mempool_view: Option<std::sync::Arc<MempoolView>>,

    /// PB-40 second-chance lookup. Wired together with
    /// `mempool_view` and `None` in exactly the same cases, but kept
    /// as its own field rather than folded into the view because the
    /// two ask bitcoind different questions: the view polls
    /// `getrawmempool` on a cadence, this asks about specific
    /// transactions plus recent blocks at the moment a template is
    /// about to be rejected.
    pub second_chance: Option<std::sync::Arc<SecondChance>>,
}

fn enforce_protocol(cfg: &PolicyConfig) -> anyhow::Result<()> {
    if cfg.protocol_version != PROTOCOL_VERSION {
        return Err(anyhow!(
            "policy.protocol_version={} does not match binary PROTOCOL_VERSION={}",
            cfg.protocol_version,
            PROTOCOL_VERSION
        ));
    }
    Ok(())
}

fn parse_policy_from_policy_table(contents: &str) -> anyhow::Result<PolicyConfig> {
    let v: toml::Value = toml::from_str(contents).context("parse TOML as value")?;

    let policy_v = v
        .get("policy")
        .cloned()
        .ok_or_else(|| anyhow!("missing [policy] table at top level"))?;

    let cfg: PolicyConfig = policy_v
        .try_into()
        .context("deserialize PolicyConfig from [policy] table")?;

    Ok(cfg)
}

pub fn load_initial_policy(path: &str) -> anyhow::Result<PolicyHolder> {
    let contents = std::fs::read_to_string(path)
        .with_context(|| format!("read policy file failed: {path}"))?;

    let cfg = parse_policy_from_policy_table(&contents)
        .with_context(|| format!("policy parse failed for {path}"))?;

    cfg.validate().context("policy validation failed")?;
    enforce_protocol(&cfg)?;

    Ok(PolicyHolder {
        config: cfg,
        toml_text: contents,
    })
}

/// Load the initial policy, refusing to boot on failure unless the operator
/// has explicitly opted in to permissive degraded operation.
///
/// PB-36. This used to swallow ANY load, parse, validation or protocol
/// failure and continue with a built-in policy that sets `min_total_fees = 0`,
/// `max_tx_count = u32::MAX` and `reject_empty_templates = false`. A
/// malformed, missing or rejected policy file did not stop the verifier; it
/// converted it into one that accepts everything. Invariant 3 forbids exactly
/// that shape: "no silent fallback". A loud ERROR line followed by a green
/// process is a silent fallback with extra steps.
///
/// **Why refusing to boot is not worse than accepting everything.** Both end
/// with unverified templates reaching miners. The difference is that a dead
/// verifier is visible: the gateway loses the heartbeat, auto-degrades, and
/// increments `svtwo_mode_transitions_total` (PB-15/16/17). An
/// accept-everything verifier is invisible: every template returns Agreed and
/// the process looks healthy. The failure is the same and only the
/// observability differs, so the fix is to make it observable.
///
/// **Refusing everything was considered and rejected.** A verifier that
/// rejects every template stops the pool mining entirely AND keeps answering
/// verdicts, so the gateway's auto-degrade never fires and miners get no jobs
/// with no signal. That is worse than exiting.
///
/// The escape hatch mirrors `VELDRA_API_SECRET_OPTIONAL`
/// (`sv2-gateway/src/main.rs:74`), which the codebase already uses to let an
/// operator acknowledge a specific risk rather than discover it. The flag is
/// read from the environment by `main.rs` and passed in, so this stays
/// testable without racing other tests over a process-global env var.
///
/// Returns the holder and whether it is the degraded built-in, so callers do
/// not have to infer that by sniffing `toml_text` for a `[policy]` substring.
pub fn safe_initial_policy(
    path: &str,
    allow_permissive_degrade: bool,
) -> anyhow::Result<(PolicyHolder, bool)> {
    match load_initial_policy(path) {
        Ok(h) => Ok((h, false)),
        Err(e) if !allow_permissive_degrade => {
            let missing = !std::path::Path::new(path).exists();
            let remedy = if missing {
                "The file does not exist. Supply one: config/README.md \
                 documents copying a tracked policy as a starting point, \
                 e.g. `cp config/policy-strict.toml config/policy.toml`."
            } else {
                "The file exists but could not be parsed or validated; the \
                 cause is in the error chain above."
            };
            Err(e.context(format!(
                "policy load failed for {path}, and the verifier will not \
                 start. {remedy} A verifier that cannot load its policy \
                 cannot verify, and the previous behaviour was to continue \
                 with a built-in policy accepting every template without fee \
                 enforcement while reporting healthy. To take that risk \
                 deliberately, set VELDRA_ALLOW_PERMISSIVE_DEGRADE=1."
            )))
        }
        Err(e) => {
            error!(error = ?e, "policy load failed");
            error!(
                "VELDRA_ALLOW_PERMISSIVE_DEGRADE=1 is set: entering degraded \
                 mode with built-in default policy, all templates will be \
                 accepted without fee enforcement"
            );

            // Use the repo-provided constructor (PolicyConfig is not Default).
            let mut cfg: PolicyConfig = PolicyConfig::default_with_protocol(PROTOCOL_VERSION);

            // Only override what is required for safe, permissive degraded operation.
            cfg.required_prevhash_len = 64;
            cfg.min_total_fees = 0;
            cfg.max_tx_count = u32::MAX;

            cfg.reject_empty_templates = false;
            cfg.reject_coinbase_zero = false;
            cfg.unknown_mempool_as_high = true;

            cfg.safety.max_weight_ratio = 0.999;

            // If validation still requires tier fields (depends on your PolicyConfig::validate),
            // fill them with a consistent zeroed set.
            if let Err(v) = cfg.validate() {
                warn!(error = ?v, "built-in default policy validation failed");
                warn!("forcing zeroed fee-tier fields to satisfy validation");

                cfg.low_mempool_tx = 0;
                cfg.high_mempool_tx = 0;
                cfg.min_avg_fee_lo = 0;
                cfg.min_avg_fee_mid = 0;
                cfg.min_avg_fee_hi = 0;

                // Re-run validation, but do not panic in degraded mode.
                if let Err(v2) = cfg.validate() {
                    error!(error = ?v2, "degraded policy still failed validation");
                }
            }

            Ok((
                PolicyHolder {
                    config: cfg,
                    toml_text: "# policy load failed; running with built-in defaults\n".to_string(),
                },
                true,
            ))
        }
    }
}

// ─────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    // PB-36: this function had NO tests at all, and state.rs had no test
    // module, while it decided whether a verifier that cannot load its policy
    // keeps running and accepts every template. The flag is a parameter rather
    // than an env read precisely so these can run in parallel without racing
    // a process-global.

    /// Per-process scratch. A fixed path raced two concurrent runs of this
    /// crate's tests, which a T2 reviewer reproduced at the stated concurrency.
    fn scratch() -> std::path::PathBuf {
        std::env::temp_dir().join(format!("rg_pb36_{}", std::process::id()))
    }

    fn write_temp(name: &str, contents: &str) -> std::path::PathBuf {
        let dir = scratch();
        std::fs::create_dir_all(&dir).unwrap();
        let p = dir.join(name);
        std::fs::write(&p, contents).unwrap();
        p
    }

    /// A policy file that actually loads, so the happy path is not asserted
    /// against a fixture that would fail for its own reasons.
    fn valid_policy_toml() -> String {
        let repo_policy =
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../deploy/policy-prod.toml");
        std::fs::read_to_string(repo_policy).expect("deploy/policy-prod.toml must exist")
    }

    /// The blocking finding from the PB-36 T2 review, turned into a test.
    ///
    /// Three dev/CI stacks named `/config/policy.toml`, which `.gitignore:45`
    /// excludes, so a fresh clone and every CI checkout booted the verifier
    /// with no policy at all. That was survivable only while a load failure
    /// degraded silently to accept-everything. Making it fatal without fixing
    /// the file the stacks name would have red-failed every PR: three CI jobs
    /// boot those stacks, four services gate on `pool-verifier` being healthy,
    /// and `docker-images` needs all three jobs.
    ///
    /// This walks every `docker-compose*.yml`, extracts the policy path each
    /// one hands the verifier, maps it back through that service's bind mount
    /// to a repo path, and loads it with the REAL loader. A stack that names a
    /// file which is absent, gitignored, or does not parse fails here instead
    /// of in CI.
    #[test]
    fn every_policy_the_shipped_stacks_reference_actually_loads() {
        let repo = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
        let mut checked = 0;
        for entry in std::fs::read_dir(&repo).unwrap() {
            let path = entry.unwrap().path();
            let name = path.file_name().unwrap().to_string_lossy().to_string();
            let is_compose = name.starts_with("docker-compose")
                && path
                    .extension()
                    .is_some_and(|e| e.eq_ignore_ascii_case("yml"));
            if !is_compose {
                continue;
            }
            let text = std::fs::read_to_string(&path).unwrap();
            for line in text.lines() {
                let Some(rest) = line.trim().strip_prefix("VELDRA_POLICY_FILE:") else {
                    continue;
                };
                let in_container = rest.trim();
                let file = in_container.rsplit('/').next().unwrap();
                // /config is bind-mounted from ./config in the dev stacks and
                // from ./deploy in setup-b; try both rather than encode which.
                let candidates = [
                    repo.join("config").join(file),
                    repo.join("deploy").join(file),
                ];
                let found = candidates.iter().find(|c| c.exists()).unwrap_or_else(|| {
                    panic!(
                        "{name} sets VELDRA_POLICY_FILE={in_container}, but {file} \
                         exists in neither config/ nor deploy/. A stack that names a \
                         policy file the repo does not carry boots a verifier with no \
                         policy, and since PB-36 that is fatal."
                    )
                });
                safe_initial_policy(found.to_str().unwrap(), false).unwrap_or_else(|e| {
                    panic!(
                        "{name} names {}, which does not load: {e:#}",
                        found.display()
                    )
                });
                checked += 1;
            }
        }
        assert!(
            checked >= 4,
            "expected to check at least the four shipped stacks, checked {checked}. \
             A parser that silently matches nothing is not a passing test."
        );
    }

    #[test]
    fn a_valid_policy_loads_and_is_not_degraded() {
        let p = write_temp("pb36_valid.toml", &valid_policy_toml());
        let (holder, degraded) = safe_initial_policy(p.to_str().unwrap(), false)
            .expect("the repo's own production policy must load");
        assert!(!degraded, "a policy that loaded must not report degraded");
        assert!(
            holder.toml_text.contains("[policy]"),
            "the holder must carry the real file text"
        );
    }

    #[test]
    fn malformed_policy_refuses_to_boot_by_default() {
        let p = write_temp("pb36_malformed.toml", "this is not TOML {{{");
        let err = safe_initial_policy(p.to_str().unwrap(), false)
            .expect_err("a malformed policy must NOT yield a running verifier");
        let msg = format!("{err:#}");
        assert!(
            msg.contains("VELDRA_ALLOW_PERMISSIVE_DEGRADE"),
            "the refusal must name the flag that would override it, or an \
             operator cannot act on it. Got: {msg}"
        );
        assert!(
            msg.contains("could not be parsed"),
            "a file that EXISTS but is malformed must not be described as \
             missing, or the operator is sent to create a file they have. \
             Got: {msg}"
        );
    }

    /// The most common way to meet this error is a fresh clone: the main
    /// compose stack binds `/config/policy.toml`, which is gitignored and
    /// operator-supplied, so `docker compose up` on a clean checkout used to
    /// boot a verifier that accepted every template. The message must point
    /// at the remedy rather than only at the override.
    #[test]
    fn a_missing_file_is_reported_as_missing_with_the_remedy() {
        let p = scratch().join("absent_for_message.toml");
        let _ = std::fs::remove_file(&p);
        let err = safe_initial_policy(p.to_str().unwrap(), false).unwrap_err();
        let msg = format!("{err:#}");
        assert!(
            msg.contains("does not exist") && msg.contains("config/README.md"),
            "a missing policy file must say it is missing and where the \
             instructions are. Got: {msg}"
        );
    }

    #[test]
    fn a_missing_policy_file_refuses_to_boot_by_default() {
        let p = scratch().join("definitely_absent.toml");
        let _ = std::fs::remove_file(&p);
        assert!(
            safe_initial_policy(p.to_str().unwrap(), false).is_err(),
            "a missing policy file must not silently become accept-everything"
        );
    }

    #[test]
    fn a_policy_missing_the_policy_table_refuses_to_boot() {
        // Parses as TOML but has no [policy] table: the shape an operator
        // produces by editing the wrong file.
        let p = write_temp("pb36_no_table.toml", "[server]\nport = 8081\n");
        assert!(
            safe_initial_policy(p.to_str().unwrap(), false).is_err(),
            "valid TOML without a [policy] table must not boot permissively"
        );
    }

    /// The escape hatch still works, and still reports what it did. If this
    /// ever fails, an operator who deliberately accepted the risk is instead
    /// looking at a verifier that will not start.
    #[test]
    fn the_opt_in_still_yields_the_permissive_policy_and_says_so() {
        let p = write_temp("pb36_optin.toml", "this is not TOML {{{");
        let (holder, degraded) = safe_initial_policy(p.to_str().unwrap(), true)
            .expect("the explicit opt-in must still boot");
        assert!(degraded, "the opt-in path must report itself as degraded");
        assert_eq!(
            holder.config.min_total_fees, 0,
            "the degraded policy is the permissive one, unchanged by PB-36"
        );
        assert!(
            !holder.toml_text.contains("[policy]"),
            "the degraded holder must not masquerade as a loaded file"
        );
    }
}
