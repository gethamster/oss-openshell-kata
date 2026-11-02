//! Reconstruct stopped generation-owned network identities after a node reboot.
use super::{
    Context, Node, Record, Result, Settings, StateDirectory, args, bail, inspect, model, network,
    owned,
};

pub(super) async fn node_boot_id(node: &Node) -> Result<String> {
    let output = node
        .node(&args(&["cat", "/proc/sys/kernel/random/boot_id"]))
        .await?;
    let value = String::from_utf8(output.stdout)?.trim().to_owned();
    uuid::Uuid::parse_str(&value).context("invalid runtime node boot identity")?;
    Ok(value)
}

fn needs_boot_reconstruction(recorded: Option<&str>, current: &str) -> bool {
    recorded.is_some_and(|recorded| recorded != current)
}

pub(super) async fn recover_boot_network(
    node: &Node,
    state: &StateDirectory,
    settings: &Settings,
    id: &str,
    record: &Record,
) -> Result<Record> {
    let current_boot = node_boot_id(node).await?;
    if !needs_boot_reconstruction(record.node_boot_id.as_deref(), &current_boot) {
        return Ok(record.clone());
    }
    let native = inspect(node, id).await?;
    owned(&native, &record.creation_nonce)?;
    model::verify_image(&native, &record.image)?;
    if native["SnapshotKey"] != record.storage_id {
        bail!("retained private snapshot identity changed across node boot");
    }
    let tasks = node.node(&args(&["ctr", "tasks", "list"])).await?;
    if String::from_utf8(tasks.stdout)?
        .lines()
        .any(|line| line.split_whitespace().next() == Some(id))
    {
        bail!("node reboot recovery requires a confirmed stopped task");
    }
    if !network::attachment_absent(node, &record.attachment).await? {
        bail!("previous boot attachment identity is unexpectedly present");
    }
    let fence =
        network::create_attachment(node, id, &record.creation_nonce, &record.attachment).await?;
    network::install(node, &settings.node_binary, id, &fence).await?;
    node.node(&args(&[
        "ip",
        "link",
        "set",
        &record.attachment.host_veth,
        "down",
    ]))
    .await?;
    let restored = Record {
        node_boot_id: Some(current_boot),
        network: Some(fence),
        hypervisor_pid: 0,
        watchdog_pid: 0,
        cgroup_path: String::new(),
        ..record.clone()
    };
    state.write(id, &restored)?;
    Ok(restored)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn volatile_proofs_are_reconstructed_only_for_a_different_recorded_boot() {
        let boot = "d145e083-ef26-4fe8-bbf4-d5ef104287ee";
        assert!(!needs_boot_reconstruction(Some(boot), boot));
        assert!(needs_boot_reconstruction(
            Some(boot),
            "544f3954-0589-46a1-aa22-eb40ea010b21"
        ));
        // Legacy Lima records preserve their existing restart behavior.
        assert!(!needs_boot_reconstruction(None, boot));
    }
}
