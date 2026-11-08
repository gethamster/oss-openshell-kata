fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut prost = tonic_prost_build::Config::new();
    prost.protoc_executable(protoc_bin_vendored::protoc_bin_path()?);
    tonic_prost_build::configure().compile_with_config(
        prost,
        &[
            "proto/compute_driver.proto",
            "proto/openshell.proto",
            "protocol/kata-guard.proto",
            "protocol/compute_driver_operation_settlement.proto",
        ],
        &["proto", "protocol"],
    )?;
    println!("cargo:rerun-if-changed=proto");
    println!("cargo:rerun-if-changed=protocol");
    Ok(())
}
