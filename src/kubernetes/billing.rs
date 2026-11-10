//! Optional hosted allocation accounting; operator state never contains guest data.
use super::{client::Client, lease, policy};
use anyhow::{Context, Result, ensure};
use serde::Deserialize;
use serde_json::{Value, json};
use std::{
    fs,
    io::Write,
    os::unix::fs::{OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
    time::Duration,
};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Config {
    url: String,
    token_file: PathBuf,
    outbox_dir: PathBuf,
    #[serde(default)]
    ca_pem: Option<String>,
}
fn http_client(ca_pem: Option<&str>) -> Result<reqwest::Client> {
    openshell_crypto::tls::ensure_default_provider();
    let mut builder = reqwest::Client::builder()
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(Duration::from_secs(5));
    if let Some(pem) = ca_pem {
        ensure!(pem.len() <= 65_536, "billing CA bundle is too large");
        let roots = reqwest::Certificate::from_pem_bundle(pem.as_bytes())?;
        ensure!(!roots.is_empty(), "billing CA bundle is empty");
        builder = builder.tls_built_in_root_certs(false);
        for root in roots {
            builder = builder.add_root_certificate(root);
        }
    }
    Ok(builder.build()?)
}
struct Billing {
    config: Config,
    token: String,
    http: reqwest::Client,
}
impl Billing {
    fn configured() -> Result<Option<Self>> {
        let Some(path) = std::env::var_os("OPENSHELL_KATA_BILLING_CONFIG") else {
            return Ok(None);
        };
        let config: Config = serde_json::from_slice(&fs::read(path)?)?;
        let url = reqwest::Url::parse(&config.url)?;
        ensure!(
            url.scheme() == "https"
                && url.username().is_empty()
                && url.password().is_none()
                && url.query().is_none()
                && url.fragment().is_none(),
            "invalid billing endpoint"
        );
        ensure!(
            config.outbox_dir.is_absolute() && config.token_file.is_absolute(),
            "billing paths must be absolute"
        );
        let meta = fs::symlink_metadata(&config.token_file)?;
        ensure!(
            meta.is_file() && meta.permissions().mode() & 0o077 == 0 && meta.len() <= 256,
            "unsafe billing authority file"
        );
        let token = fs::read_to_string(&config.token_file)?.trim().to_owned();
        ensure!(token.len() >= 32, "invalid billing authority");
        fs::create_dir_all(&config.outbox_dir)?;
        fs::set_permissions(&config.outbox_dir, fs::Permissions::from_mode(0o700))?;
        let http = http_client(config.ca_pem.as_deref())?;
        Ok(Some(Self {
            config,
            token,
            http,
        }))
    }
    fn path(&self, generation: &str, extension: &str) -> Result<PathBuf> {
        uuid::Uuid::parse_str(generation)?;
        Ok(self
            .config
            .outbox_dir
            .join(format!("{generation}.{extension}")))
    }
    async fn post(&self, path: &str, value: &Value) -> Result<Value> {
        let response = self
            .http
            .post(format!("{}{path}", self.config.url.trim_end_matches('/')))
            .bearer_auth(&self.token)
            .json(value)
            .send()
            .await?;
        ensure!(
            response.status().is_success(),
            "billing authority did not acknowledge operation"
        );
        Ok(response.json().await?)
    }
    fn save(&self, path: &Path, value: &Value) -> Result<()> {
        let tmp = self
            .config
            .outbox_dir
            .join(format!(".{}.tmp", uuid::Uuid::new_v4()));
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&tmp)?;
        file.write_all(&serde_json::to_vec(value)?)?;
        file.sync_all()?;
        fs::rename(tmp, path)?;
        fs::File::open(&self.config.outbox_dir)?.sync_all()?;
        Ok(())
    }
    async fn publish(&self, value: &Value) -> Result<()> {
        let generation = value["generation"]
            .as_str()
            .context("missing billing generation")?;
        let path = self.path(generation, "json")?;
        self.save(&path, value)?;
        self.post("/api/internal/billing/sandboxes", value).await?;
        if !value["releasedAt"].is_null() {
            fs::rename(&path, self.path(generation, "settled")?)?;
        }
        Ok(())
    }
}

pub(super) async fn reserve(workspace: &str, generation: &str) -> Result<()> {
    let Some(billing) = Billing::configured()? else {
        return Ok(());
    };
    let result=billing.post("/api/internal/billing/sandbox-reservations",&json!({"resourceId":workspace,"generation":generation,"cpuMillis":2000,"memoryBytes":4_i64*1024*1024*1024})).await?;
    if result["enrolled"] == true {
        billing.save(
            &billing.path(generation, "enrolled")?,
            &json!({"resourceId":workspace}),
        )?;
    }
    Ok(())
}

pub(super) async fn observe(workspace: &str, pod: &Value) -> Result<()> {
    let Some(billing) = Billing::configured()? else {
        return Ok(());
    };
    let generation = pod["metadata"]["annotations"][lease::NONCE]
        .as_str()
        .context("missing launch generation")?;
    ensure!(
        !billing.path(generation, "settled")?.exists(),
        "a released generation requires a fresh start"
    );
    if !billing.path(generation, "enrolled")?.exists() {
        return Ok(());
    }
    let Some(start) = pod["status"]["conditions"]
        .as_array()
        .and_then(|conditions| {
            conditions
                .iter()
                .find(|c| c["type"] == "PodScheduled" && c["status"] == "True")
        })
        .and_then(|c| c["lastTransitionTime"].as_str())
    else {
        return Ok(());
    };
    let allocated = chrono::DateTime::parse_from_rfc3339(start)?.timestamp_millis();
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?
        .as_millis() as i64;
    ensure!(allocated <= now, "allocation timestamp is in the future");
    let (cpu, memory_gib) = billed_resources(&pod["spec"]["containers"][0]["resources"])?;
    let stamp = chrono::DateTime::from_timestamp_millis(now)
        .context("invalid observation time")?
        .to_rfc3339();
    billing.publish(&json!({"resourceId":workspace,"generation":generation,"sandboxId":pod["metadata"]["annotations"][lease::SANDBOX],"cpuMillis":u64::from(cpu)*1000,"memoryBytes":i64::from(memory_gib)*1024*1024*1024,"allocatedAt":start,"observedAt":stamp,"releasedAt":null})).await?;
    reserve(workspace, generation).await
}

/// The guest's whole vCPUs and GiB memory: requests equal limits and stay within
/// the hosted resource-shape ceiling. The default shape bills 2000 millicores and 4 GiB.
fn billed_resources(resources: &Value) -> Result<(u32, u32)> {
    let (requests, limits) = (&resources["requests"], &resources["limits"]);
    ensure!(
        requests["cpu"] == limits["cpu"] && requests["memory"] == limits["memory"],
        "billing resource profile differs"
    );
    let cpu: u32 = requests["cpu"]
        .as_str()
        .context("billing resource profile differs")?
        .parse()
        .context("billing resource profile differs")?;
    let memory_gib: u32 = requests["memory"]
        .as_str()
        .and_then(|memory| memory.strip_suffix("Gi"))
        .context("billing resource profile differs")?
        .parse()
        .context("billing resource profile differs")?;
    ensure!(
        (1..=crate::resource_shape::MAX_CPU).contains(&cpu)
            && (1..=crate::resource_shape::MAX_MEMORY_GIB).contains(&memory_gib),
        "billing resource profile differs"
    );
    Ok((cpu, memory_gib))
}

pub(super) async fn release(generation: &str) -> Result<()> {
    let Some(billing) = Billing::configured()? else {
        return Ok(());
    };
    let path = billing.path(generation, "json")?;
    if !path.exists() {
        return Ok(());
    }
    let mut value: Value = serde_json::from_slice(&fs::read(path)?)?;
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?
        .as_millis() as i64;
    let stamp = chrono::DateTime::from_timestamp_millis(now)
        .context("invalid release time")?
        .to_rfc3339();
    if value["releasedAt"].is_null() {
        value["releasedAt"] = json!(stamp);
        value["observedAt"] = value["releasedAt"].clone();
    }
    billing.publish(&value).await
}

/// Retry buffered receipts and close generations only after an authoritative absence check.
pub(super) async fn reconcile(client: &Client, workspace: &str, _pods: &[Value]) -> Result<()> {
    let Some(billing) = Billing::configured()? else {
        return Ok(());
    };
    for entry in fs::read_dir(&billing.config.outbox_dir)?
        .filter(|entry| {
            entry.is_err()
                || entry
                    .as_ref()
                    .is_ok_and(|entry| entry.path().extension().is_some_and(|ext| ext == "json"))
        })
        .take(1000)
    {
        let path = entry?.path();
        if path.extension().is_none_or(|ext| ext != "json") {
            continue;
        }
        let value: Value = serde_json::from_slice(&fs::read(&path)?)?;
        if value["resourceId"] != workspace {
            continue;
        }
        let generation = value["generation"].as_str().context("missing generation")?;
        let sandbox = value["sandboxId"].as_str().context("missing sandbox")?;
        let pod = client
            .get(
                "pod",
                Some(&policy::resource_id(sandbox)?),
                Some(&policy::namespace(workspace)?),
            )
            .await?;
        if pod.is_none() {
            release(generation).await?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    #[test]
    fn billing_client_starts_without_a_process_provider() {
        const CHILD: &str = "KATA_BILLING_PROVIDER_TEST_CHILD";
        if std::env::var_os(CHILD).is_some() {
            assert!(super::http_client(None).is_ok());
            assert!(super::http_client(Some("")).is_err());
            assert!(super::http_client(Some("not a CA certificate")).is_err());
            return;
        }
        let output = std::process::Command::new(std::env::current_exe().expect("test binary"))
            .args([
                "--exact",
                "kubernetes::billing::tests::billing_client_starts_without_a_process_provider",
                "--nocapture",
            ])
            .env(CHILD, "1")
            .output()
            .expect("fresh billing process");
        assert!(
            output.status.success(),
            "{}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }

    #[test]
    fn observe_refuses_a_settled_generation() {
        use std::os::unix::fs::PermissionsExt;
        const CHILD: &str = "KATA_BILLING_SETTLED_TEST_CHILD";
        const GENERATION: &str = "00000000-0000-4000-8000-000000000001";
        if let Some(dir) = std::env::var_os(CHILD) {
            let outbox = std::path::Path::new(&dir).join("outbox");
            let pod = serde_json::json!({
                "metadata":{"annotations":{(super::lease::NONCE):GENERATION,(super::lease::SANDBOX):"sandbox"}},
                "status":{"conditions":[{"type":"PodScheduled","status":"True","lastTransitionTime":"2020-01-01T00:00:00Z"}]},
                "spec":{"containers":[{"resources":{"requests":{"cpu":"2","memory":"4Gi"},"limits":{"cpu":"2","memory":"4Gi"}}}]}});
            let result = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("runtime")
                .block_on(super::observe("workspace", &pod));
            let error = result.expect_err("settled generation must be refused");
            assert!(
                format!("{error:#}").contains("a released generation requires a fresh start"),
                "{error:#}"
            );
            assert!(!outbox.join(format!("{GENERATION}.json")).exists());
            assert!(outbox.join(format!("{GENERATION}.settled")).exists());
            return;
        }
        let dir = tempfile::tempdir().expect("temp dir");
        let outbox = dir.path().join("outbox");
        std::fs::create_dir(&outbox).expect("outbox");
        std::fs::write(outbox.join(format!("{GENERATION}.enrolled")), "{}").expect("enrolled");
        std::fs::write(outbox.join(format!("{GENERATION}.settled")), "{}").expect("settled");
        let token = dir.path().join("token");
        std::fs::write(&token, "t".repeat(32)).expect("token");
        std::fs::set_permissions(&token, std::fs::Permissions::from_mode(0o600)).expect("mode");
        let config = dir.path().join("config.json");
        std::fs::write(
            &config,
            serde_json::to_vec(&serde_json::json!({
                "url":"https://127.0.0.1:9","token_file":token,"outbox_dir":outbox}))
            .expect("config"),
        )
        .expect("config");
        let output = std::process::Command::new(std::env::current_exe().expect("test binary"))
            .args([
                "--exact",
                "kubernetes::billing::tests::observe_refuses_a_settled_generation",
                "--nocapture",
            ])
            .env(CHILD, dir.path())
            .env("OPENSHELL_KATA_BILLING_CONFIG", &config)
            .output()
            .expect("fresh billing process");
        assert!(
            output.status.success(),
            "{}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }
}
