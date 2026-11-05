"""Build and retain the Kata adapter binaries for managed publication."""
import json
from typing import Annotated
import dagger
from dagger import DefaultPath, dag, function, object_type

RUST = "rust@sha256:620dbcd124499c59e2406d3741574b5c5838cf9eb9656f0c3a03948f79b02959"
UBUNTU = "ubuntu@sha256:076e7bf82319619f28dd0aa9c02ab34b055ad37100395b4f49a2ffba04fb5e11"
PLATFORMS = {"linux/amd64": "linux-amd64", "linux/arm64": "linux-arm64"}


@object_type
class KataBuild:
    def container(self, platform: str, source: dagger.Directory, variables: str) -> dagger.Container:
        if platform not in PLATFORMS:
            raise ValueError("Use the enrolled native worker for macOS")
        toolchain = dag.container(platform=dagger.Platform(platform)).from_(RUST)
        result = (dag.container(platform=dagger.Platform(platform)).from_(UBUNTU)
                  .with_exec(["sh", "-ec", "apt-get update && apt-get install -y --no-install-recommends build-essential clang cmake ca-certificates git python3 pkg-config libssl-dev && rm -rf /var/lib/apt/lists/*"])
                  .with_directory("/usr/local/rustup", toolchain.directory("/usr/local/rustup"))
                  .with_directory("/usr/local/cargo", toolchain.directory("/usr/local/cargo"))
                  .with_env_variable("PATH", "/usr/local/cargo/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin")
                  .with_env_variable("RUSTUP_HOME", "/usr/local/rustup")
                  .with_env_variable("CARGO_HOME", "/usr/local/cargo")
                  .with_env_variable("RUSTUP_TOOLCHAIN", "1.98.0")
                  .with_mounted_cache("/usr/local/cargo/registry", dag.cache_volume("kata-cargo-registry"))
                  .with_mounted_cache("/target", dag.cache_volume("kata-target-" + platform.replace("/", "-")))
                  .with_env_variable("CARGO_TARGET_DIR", "/target")
                  .with_env_variable("CARGO_BUILD_JOBS", "2")
                  .with_env_variable("CARGO_INCREMENTAL", "0")
                  .with_env_variable("CC", "clang")
                  .with_env_variable("RUST_TEST_THREADS", "1")
                  .with_directory("/source", source, exclude=["target", ".git", "dist-native"])
                  .with_workdir("/source"))
        for name, value in json.loads(variables).items():
            if name in {"PATH", "HOME", "CARGO_HOME", "CARGO_TARGET_DIR", "RUSTUP_HOME", "RUSTUP_TOOLCHAIN", "CARGO_BUILD_JOBS", "CARGO_INCREMENTAL", "CC", "RUST_TEST_THREADS"}:
                raise ValueError("Variable conflicts with the pinned toolchain")
            result = result.with_env_variable(name, value)
        return result

    @function
    async def test(self, platform: str, source: Annotated[dagger.Directory, DefaultPath("/")], variables: str = "{}") -> str:
        return await (self.container(platform, source, variables)
                      .with_exec(["cargo", "test", "--locked", "--release", "--all-targets", "--all-features"])
                      .with_exec(["cargo", "run", "--locked", "--release", "--bin", "kata-dev", "--", "verify-upstream"]).stdout())

    @function
    def build(self, platform: str, source: Annotated[dagger.Directory, DefaultPath("/")], variables: str = "{}") -> dagger.Directory:
        return (self.container(platform, source, variables)
                .with_exec(["cargo", "build", "--locked", "--release", "--all-features", "--bins"])
                .with_exec(["python3", "scripts/package-managed.py", "--target-dir", "/target/release", "--platform", PLATFORMS[platform], "--output", "/output"])
                .directory("/output"))
