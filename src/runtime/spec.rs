//! Minimal OCI configuration with no host-backed files, devices, or shared exports.
use serde_json::{Value, json};

/// Build a rootful guest configuration inside an already fenced VM boundary.
pub fn guest_spec(id: &str, netns: &str, proxy: &str) -> Value {
    guest_spec_for(
        id,
        netns,
        proxy,
        &crate::boundary::process::VmLimits {
            vcpus: 1,
            memory_mib: 2048,
            disk_mib: 2048,
            lifetime_secs: 3600,
        },
    )
}

/// Build a guest specification for the exact admitted operator resource profile.
pub fn guest_spec_for(
    id: &str,
    netns: &str,
    proxy: &str,
    resources: &crate::boundary::process::VmLimits,
) -> Value {
    let caps = [
        "CAP_CHOWN",
        "CAP_DAC_OVERRIDE",
        "CAP_DAC_READ_SEARCH",
        "CAP_FOWNER",
        "CAP_FSETID",
        "CAP_KILL",
        "CAP_SETGID",
        "CAP_SETUID",
        "CAP_SETPCAP",
        "CAP_LINUX_IMMUTABLE",
        "CAP_NET_BIND_SERVICE",
        "CAP_NET_BROADCAST",
        "CAP_NET_ADMIN",
        "CAP_NET_RAW",
        "CAP_IPC_LOCK",
        "CAP_IPC_OWNER",
        "CAP_SYS_MODULE",
        "CAP_SYS_RAWIO",
        "CAP_SYS_CHROOT",
        "CAP_SYS_PTRACE",
        "CAP_SYS_PACCT",
        "CAP_SYS_ADMIN",
        "CAP_SYS_BOOT",
        "CAP_SYS_NICE",
        "CAP_SYS_RESOURCE",
        "CAP_SYS_TIME",
        "CAP_SYS_TTY_CONFIG",
        "CAP_MKNOD",
        "CAP_LEASE",
        "CAP_AUDIT_WRITE",
        "CAP_AUDIT_CONTROL",
        "CAP_SETFCAP",
        "CAP_MAC_OVERRIDE",
        "CAP_MAC_ADMIN",
        "CAP_SYSLOG",
        "CAP_WAKE_ALARM",
        "CAP_BLOCK_SUSPEND",
        "CAP_AUDIT_READ",
        "CAP_PERFMON",
        "CAP_BPF",
        "CAP_CHECKPOINT_RESTORE",
    ];
    json!({"ociVersion":"1.1.0","annotations":{"io.katacontainers.config.hypervisor.default_vcpus":resources.vcpus.to_string(),"io.katacontainers.config.hypervisor.default_memory":resources.memory_mib.to_string()},"process":{"terminal":false,"user":{"uid":0,"gid":0},"args":["/usr/local/sbin/openshell-kata-init"],"env":["PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",format!("HTTP_PROXY={proxy}"),format!("HTTPS_PROXY={proxy}"),"NO_PROXY=localhost,127.0.0.1,::1","DOCKER_TLS_CERTDIR="],"cwd":"/","capabilities":{"bounding":&caps[..],"effective":&caps[..],"inheritable":&caps[..],"permitted":&caps[..],"ambient":&caps[..]},"rlimits":[{"type":"RLIMIT_NOFILE","hard":65536,"soft":65536}]},"root":{"path":"rootfs","readonly":false},"hostname":"openshell","mounts":[{"destination":"/run","type":"tmpfs","source":"tmpfs","options":["nosuid","nodev","mode=755","size=65536k"]},{"destination":"/proc","type":"proc","source":"proc","options":["nosuid","noexec","nodev"]},{"destination":"/dev","type":"tmpfs","source":"tmpfs","options":["nosuid","strictatime","mode=755","size=65536k"]},{"destination":"/dev/pts","type":"devpts","source":"devpts","options":["nosuid","noexec","newinstance","ptmxmode=0666","mode=0620"]},{"destination":"/dev/shm","type":"tmpfs","source":"shm","options":["nosuid","nodev","mode=1777","size=65536k"]},{"destination":"/sys","type":"sysfs","source":"sysfs","options":["nosuid","noexec","nodev","ro"]}],"linux":{"cgroupsPath":format!("/openshell-kata/{id}/guest"),"resources":{"memory":{"limit":super::model::guest_memory_bytes(resources)},"cpu":{"quota":u64::from(resources.vcpus) * 100000,"period":100000},"devices":[{"allow":true,"access":"rwm"}]},"devices":[],"namespaces":[{"type":"pid"},{"type":"ipc"},{"type":"uts"},{"type":"mount"},{"type":"network","path":netns}]}})
}
