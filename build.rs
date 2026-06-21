//! Generate the gRPC **client** stubs from the vendored `.proto` files (copied
//! from sylva-server — see `proto/` + `cargo run --bin sync-proto`).
//!
//! Uses `protox` (pure-Rust protobuf compiler) → `FileDescriptorSet`, then
//! `tonic-prost-build`, so the build needs no system `protoc`. Client-only: the
//! SDK calls Sylva Server, it doesn't serve.

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Vendored under this crate's `proto/`.
    const PLATFORM_PROTO: &str = "proto/platform/v1/platform.proto";
    const ACCOUNT_PROTO: &str = "proto/account/v1/account.proto";
    const INCLUDE: &str = "proto";

    println!("cargo:rerun-if-changed={PLATFORM_PROTO}");
    println!("cargo:rerun-if-changed={ACCOUNT_PROTO}");
    println!("cargo:rerun-if-changed={INCLUDE}");

    let file_descriptors = protox::compile([PLATFORM_PROTO, ACCOUNT_PROTO], [INCLUDE])?;
    // Client stubs are what the SDK ships; the server stubs are generated too so
    // tests can stand up an in-process mock server to exercise the client.
    tonic_prost_build::configure()
        .build_server(true)
        .build_client(true)
        .compile_fds(file_descriptors)?;
    Ok(())
}
