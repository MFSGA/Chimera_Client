use std::{fs, path::Path};

const ALLOWED_DIRECT_CONNECT_FILES: &[&str] = &[
    "clash-lib/src/proxy/tun/mod.rs",
    "clash-lib/src/proxy/utils/socket_helpers.rs",
];

const ALLOWED_DIRECT_BIND_FILES: &[&str] = &[
    "clash-lib/src/proxy/direct/mod.rs",
    "clash-lib/src/proxy/direct/datagram.rs",
    "clash-lib/src/proxy/tun/mod.rs",
    "clash-lib/src/proxy/utils/socket_helpers.rs",
];

#[test]
fn proxy_runtime_tcp_connects_use_socket_helper() {
    assert_no_forbidden_runtime_usage(
        Path::new(env!("CARGO_MANIFEST_DIR")).join("src/proxy"),
        "TcpStream::connect",
        ALLOWED_DIRECT_CONNECT_FILES,
    );
}

#[test]
fn proxy_runtime_udp_binds_use_socket_helper() {
    assert_no_forbidden_runtime_usage(
        Path::new(env!("CARGO_MANIFEST_DIR")).join("src/proxy"),
        "UdpSocket::bind",
        ALLOWED_DIRECT_BIND_FILES,
    );
}

fn assert_no_forbidden_runtime_usage(
    root: impl AsRef<Path>,
    needle: &str,
    allowed_files: &[&str],
) {
    let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut violations = Vec::new();
    visit_rs_files(root.as_ref(), &mut |path| {
        let rel = path
            .strip_prefix(manifest_dir.parent().expect("workspace root"))
            .expect("path should be under workspace")
            .to_string_lossy()
            .replace('\\', "/");

        if allowed_files.iter().any(|allowed| *allowed == rel) {
            return;
        }

        let content = fs::read_to_string(path).expect("read source file");
        let runtime_content = content
            .split("\n#[cfg(test)]")
            .next()
            .unwrap_or(content.as_str());
        for (idx, line) in runtime_content.lines().enumerate() {
            if line.contains(needle) {
                violations.push(format!("{rel}:{}: {}", idx + 1, line.trim()));
            }
        }
    });

    assert!(
        violations.is_empty(),
        "runtime proxy code must use socket_helpers for {needle}; violations:\n{}",
        violations.join("\n")
    );
}

fn visit_rs_files(dir: &Path, f: &mut impl FnMut(&Path)) {
    for entry in fs::read_dir(dir).expect("read source directory") {
        let entry = entry.expect("read directory entry");
        let path = entry.path();
        if path.is_dir() {
            visit_rs_files(&path, f);
        } else if path.extension().is_some_and(|ext| ext == "rs") {
            f(&path);
        }
    }
}
