use std::{io::Write as _, path::Path, process::Stdio};

pub(super) fn write(path: &Path, source: &str) {
    // Materialize the executable in a child. Other concurrently spawning tests
    // must not inherit a writable script descriptor and make exec return ETXTBSY.
    let mut writer = std::process::Command::new("/bin/sh")
        .args(["-c", "cat > \"$1\" && chmod 700 \"$1\"", "fixture-writer"])
        .arg(path)
        .stdin(Stdio::piped())
        .spawn()
        .expect("launch fixture writer");
    writer
        .stdin
        .take()
        .expect("fixture writer input")
        .write_all(source.as_bytes())
        .expect("write fixture source");
    assert!(writer.wait().expect("wait for fixture writer").success());
}
