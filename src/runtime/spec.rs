//! Minimal OCI configuration with no host-backed files, devices, or shared exports.
use super::model::LOCAL_GUEST_MEMORY_BYTES;
use serde_json::{Value, json};

/// Build a rootful guest configuration inside an already fenced VM boundary.
pub fn guest_spec(id: &str, netns: &str, proxy: &str) -> Value {
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
    json!({"ociVersion":"1.1.0","process":{"terminal":false,"user":{"uid":0,"gid":0},"args":["/usr/local/sbin/openshell-kata-init"],"env":["PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",format!("HTTP_PROXY={proxy}"),format!("HTTPS_PROXY={proxy}"),"NO_PROXY=localhost,127.0.0.1,::1","DOCKER_TLS_CERTDIR="],"cwd":"/","capabilities":{"bounding":&caps[..],"effective":&caps[..],"inheritable":&caps[..],"permitted":&caps[..],"ambient":&caps[..]},"rlimits":[{"type":"RLIMIT_NOFILE","hard":65536,"soft":65536}]},"root":{"path":"rootfs","readonly":false},"hostname":"openshell","mounts":[{"destination":"/run","type":"tmpfs","source":"tmpfs","options":["nosuid","nodev","mode=755","size=65536k"]},{"destination":"/proc","type":"proc","source":"proc","options":["nosuid","noexec","nodev"]},{"destination":"/dev","type":"tmpfs","source":"tmpfs","options":["nosuid","strictatime","mode=755","size=65536k"]},{"destination":"/dev/pts","type":"devpts","source":"devpts","options":["nosuid","noexec","newinstance","ptmxmode=0666","mode=0620"]},{"destination":"/dev/shm","type":"tmpfs","source":"shm","options":["nosuid","nodev","mode=1777","size=65536k"]},{"destination":"/sys","type":"sysfs","source":"sysfs","options":["nosuid","noexec","nodev","ro"]}],"linux":{"cgroupsPath":format!("/openshell-kata/{id}/guest"),"resources":{"memory":{"limit":LOCAL_GUEST_MEMORY_BYTES},"cpu":{"quota":100000,"period":100000},"devices":[{"allow":true,"access":"rwm"}]},"devices":[],"namespaces":[{"type":"pid"},{"type":"ipc"},{"type":"uts"},{"type":"mount"},{"type":"network","path":netns}]}})
}
