use super::*;

#[cfg(target_os = "linux")]
#[test]
fn stale_process_record_can_be_replaced_after_controller_exit() {
    let directory = tempfile::tempdir().expect("workspace");
    let workspace = Workspace::open(directory.path()).expect("open workspace");
    let id = Uuid::new_v4().to_string();
    let pid = rustix::process::getpid();
    let current = Record {
        version: 1,
        pid: pid.as_raw_nonzero().get() as u32,
        start: identity(pid).expect("current process").start,
    };
    for id in [id.clone(), format!("{id}.hold")] {
        let stale = Record {
            start: 0,
            ..current
        };
        publish_record(&workspace, &id, &stale).expect("old process identity");
        publish_record(&workspace, &id, &current).expect("replace stale identity");
        assert_eq!(
            read_record(&workspace, &id).expect("record").as_ref(),
            Some(&current)
        );
    }
}

#[cfg(target_os = "linux")]
#[test]
fn live_process_record_cannot_be_replaced() {
    let directory = tempfile::tempdir().expect("workspace");
    let workspace = Workspace::open(directory.path()).expect("open workspace");
    let id = Uuid::new_v4().to_string();
    let pid = rustix::process::getpid();
    let current = Record {
        version: 1,
        pid: pid.as_raw_nonzero().get() as u32,
        start: identity(pid).expect("current process").start,
    };
    publish_record(&workspace, &id, &current).expect("live identity");
    assert!(publish_record(&workspace, &id, &current).is_err());
    assert!(cleanup_record(&workspace, &id, current.pid).is_err());
    assert_eq!(read_record(&workspace, &id).expect("record"), Some(current));
}

#[cfg(target_os = "linux")]
#[test]
fn concurrent_restarts_publish_only_one_live_identity() {
    let directory = tempfile::tempdir().expect("workspace");
    let workspace = Workspace::open(directory.path()).expect("open workspace");
    let id = Uuid::new_v4().to_string();
    let pid = rustix::process::getpid();
    let current = Record {
        version: 1,
        pid: pid.as_raw_nonzero().get() as u32,
        start: identity(pid).expect("current process").start,
    };
    publish_record(
        &workspace,
        &id,
        &Record {
            start: 0,
            ..current
        },
    )
    .expect("old identity");
    let barrier = std::sync::Barrier::new(8);
    let published = std::thread::scope(|scope| {
        let workers: Vec<_> = (0..8)
            .map(|_| {
                scope.spawn(|| {
                    let workspace = Workspace::open(directory.path()).expect("workspace");
                    barrier.wait();
                    publish_record(&workspace, &id, &current).is_ok()
                })
            })
            .collect();
        workers
            .into_iter()
            .map(|worker| worker.join().expect("worker"))
            .filter(|published| *published)
            .count()
    });
    assert_eq!(published, 1);
    assert_eq!(read_record(&workspace, &id).expect("record"), Some(current));
}

#[cfg(target_os = "linux")]
#[test]
fn retained_process_evidence_prevents_stale_record_replacement() {
    for suffix in [
        "cancel.json",
        "cancel-ack.json",
        "cancelled",
        "drain-failed",
        "capability.json",
    ] {
        let directory = tempfile::tempdir().expect("workspace");
        let workspace = Workspace::open(directory.path()).expect("open workspace");
        let id = Uuid::new_v4().to_string();
        let stale = Record {
            version: 1,
            pid: u32::MAX / 2,
            start: 1,
        };
        publish_record(&workspace, &id, &stale).expect("old identity");
        let evidence = directory
            .path()
            .join(RECORD_DIRECTORY)
            .join(format!("{id}.{suffix}"));
        std::fs::write(&evidence, b"retained").expect("retained evidence");
        assert!(
            publish_record(&workspace, &id, &stale).is_err(),
            "replaced {suffix}"
        );
        assert_eq!(
            std::fs::read(&evidence).expect("evidence remains"),
            b"retained"
        );
        assert_eq!(read_record(&workspace, &id).expect("record"), Some(stale));
    }
}

#[test]
fn invalid_process_records_are_preserved() {
    for bytes in [
        b"not JSON".as_slice(),
        br#"{"version":2,"pid":2147483647,"start":1}"#,
        br#"{"version":1,"pid":0,"start":1}"#,
    ] {
        let directory = tempfile::tempdir().expect("workspace");
        let workspace = Workspace::open(directory.path()).expect("open workspace");
        let id = Uuid::new_v4().to_string();
        let records = process_directory(&workspace).expect("process directory");
        let name = format!("{id}.json");
        records.write(&name, bytes).expect("invalid record");
        let replacement = Record {
            version: 1,
            pid: 1,
            start: 1,
        };
        assert!(publish_record(&workspace, &id, &replacement).is_err());
        assert_eq!(records.read(&name).expect("retained record"), bytes);
    }
}
