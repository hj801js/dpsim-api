use std::process::Command;

fn main() {
    // Embed the short git SHA at build time so /version can report the exact
    // checkout. Falls back to "unknown" outside a git checkout (e.g. vendored
    // tarball) so the build never breaks.
    let sha = Command::new("git")
        .args(["rev-parse", "--short", "HEAD"])
        .output()
        .ok()
        .and_then(|o| {
            if o.status.success() {
                String::from_utf8(o.stdout).ok()
            } else {
                None
            }
        })
        .map(|s| s.trim().to_owned())
        .unwrap_or_else(|| "unknown".into());
    println!("cargo:rustc-env=DPSIM_API_GIT_SHA={}", sha);
    // Only rebuild when HEAD moves — avoids recompiling on every `cargo build`.
    println!("cargo:rerun-if-changed=.git/HEAD");
    println!("cargo:rerun-if-changed=.git/refs");
}
