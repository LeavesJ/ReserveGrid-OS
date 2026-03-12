use anyhow::{Context, Result, bail};
use serde::Deserialize;
use std::fs;
use std::path::Path;

#[derive(Debug, Deserialize)]
struct RootWrapper {
    manager: ManagerTable,
}

#[derive(Debug, Deserialize, Clone)]
struct ManagerTable {
    backend: String,
    poll_interval_secs: Option<u64>,

    // Common routing
    verifier_tcp_addr: Option<String>,
    http_listen_addr: Option<String>,

    // Flat bitcoind (your screenshot manager.toml)
    rpc_url: Option<String>,
    rpc_user: Option<String>,
    rpc_pass: Option<String>,

    // Coinbase construction
    coinbase_output_script_hex: Option<String>,
    extranonce_size: Option<usize>,

    // Flat stratum (older)
    stratum_addr: Option<String>,
    stratum_auth: Option<String>,

    // Nested forms (older examples)
    bitcoind: Option<BitcoindNested>,
    stratum: Option<StratumNested>,
}

#[derive(Debug, Deserialize, Clone)]
#[allow(clippy::struct_field_names)]
struct BitcoindNested {
    rpc_url: String,
    rpc_user: String,
    rpc_pass: String,
}

#[derive(Debug, Deserialize, Clone)]
struct StratumNested {
    addr: String,
    auth: Option<String>,
}

#[derive(Debug, Clone)]
pub struct TemplateManagerConfig {
    pub backend: String,
    pub poll_interval_secs: Option<u64>,

    pub verifier_tcp_addr: Option<String>,
    pub http_listen_addr: Option<String>,

    pub rpc_url: Option<String>,
    pub rpc_user: Option<String>,
    pub rpc_pass: Option<String>,

    pub stratum_addr: Option<String>,
    pub stratum_auth: Option<String>,

    /// Hex-encoded scriptPubKey for the coinbase output. Default: "51" (`OP_TRUE`).
    pub coinbase_output_script_hex: String,
    /// Size of the extranonce space in bytes. Must match the gateway. Default: 4.
    pub extranonce_size: usize,
}

fn manager_table_from_value(contents: &str) -> Result<ManagerTable> {
    let v: toml::Value = toml::from_str(contents).context("parse TOML as value")?;

    let mgr_v = v
        .get("manager")
        .cloned()
        .context("missing [manager] table at top level")?;

    let mgr: ManagerTable = mgr_v.try_into().context("deserialize manager table")?;

    Ok(mgr)
}

impl TemplateManagerConfig {
    pub fn from_path<P: AsRef<Path>>(path: P) -> Result<Self> {
        let path_ref = path.as_ref();
        let contents = fs::read_to_string(path_ref).with_context(|| {
            format!("failed to read manager config file {}", path_ref.display())
        })?;

        // First try wrapper, then table extraction (robust).
        let mgr = match toml::from_str::<RootWrapper>(&contents) {
            Ok(w) => w.manager,
            Err(_) => manager_table_from_value(&contents).with_context(|| {
                format!("failed to parse manager config in {}", path_ref.display())
            })?,
        };

        let cfg = Self::normalize(mgr);
        cfg.validate()
            .with_context(|| format!("invalid manager config in {}", path_ref.display()))?;
        Ok(cfg)
    }

    fn normalize(mgr: ManagerTable) -> Self {
        let mut rpc_url = mgr.rpc_url;
        let mut rpc_user = mgr.rpc_user;
        let mut rpc_pass = mgr.rpc_pass;

        let mut stratum_addr = mgr.stratum_addr;
        let mut stratum_auth = mgr.stratum_auth;

        if let Some(b) = mgr.bitcoind {
            rpc_url = Some(b.rpc_url);
            rpc_user = Some(b.rpc_user);
            rpc_pass = Some(b.rpc_pass);
        }

        if let Some(s) = mgr.stratum {
            stratum_addr = Some(s.addr);
            stratum_auth = s.auth;
        }

        TemplateManagerConfig {
            backend: mgr.backend,
            poll_interval_secs: mgr.poll_interval_secs,

            verifier_tcp_addr: mgr.verifier_tcp_addr,
            http_listen_addr: mgr.http_listen_addr,

            rpc_url,
            rpc_user,
            rpc_pass,

            stratum_addr,
            stratum_auth,

            coinbase_output_script_hex: mgr
                .coinbase_output_script_hex
                .unwrap_or_else(|| "51".to_string()),
            extranonce_size: mgr.extranonce_size.unwrap_or(4),
        }
    }

    pub fn validate(&self) -> Result<()> {
        match self.backend.as_str() {
            "bitcoind" => {
                if let Some(p) = self.poll_interval_secs
                    && p == 0
                {
                    bail!("poll_interval_secs must be >= 1");
                }
            }
            "stratum" => {
                let addr = self.stratum_addr.as_ref().map_or("", |s| s.trim());
                if addr.is_empty() {
                    bail!(
                        "backend=stratum requires manager.stratum_addr or [manager.stratum].addr"
                    );
                }
            }
            other => bail!("unsupported backend {other:?} (expected \"bitcoind\" or \"stratum\")"),
        }

        if hex::decode(&self.coinbase_output_script_hex).is_err() {
            bail!(
                "coinbase_output_script_hex is not valid hex: {:?}",
                self.coinbase_output_script_hex
            );
        }
        if self.extranonce_size == 0 || self.extranonce_size > 32 {
            bail!(
                "extranonce_size must be 1..=32, got {}",
                self.extranonce_size
            );
        }

        Ok(())
    }
}
