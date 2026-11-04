//! Optional hosted allocation accounting; operator state never contains guest data.
use super::{client::Client, lease, manifest, policy};
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
        let http = reqwest::Client::builder()
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .timeout(Duration::from_secs(5))
            .build()?;
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
    let resources = &pod["spec"]["containers"][0]["resources"];
    ensure!(
        resources["requests"]["cpu"] == manifest::limits()["cpu"]
            && resources["requests"]["memory"] == manifest::limits()["memory"],
        "billing resource profile differs"
    );
    let stamp = chrono::DateTime::from_timestamp_millis(now)
        .context("invalid observation time")?
        .to_rfc3339();
    billing.publish(&json!({"resourceId":workspace,"generation":generation,"sandboxId":pod["metadata"]["annotations"][lease::SANDBOX],"cpuMillis":2000,"memoryBytes":4_i64*1024*1024*1024,"allocatedAt":start,"observedAt":stamp,"releasedAt":null})).await?;
    reserve(workspace, generation).await
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
    for entry in fs::read_dir(&billing.config.outbox_dir)?.take(1000) {
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
