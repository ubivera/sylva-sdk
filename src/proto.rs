//! Generated gRPC **client** stubs for the Sylva Server APIs (`sylva.account.v1` +
//! `sylva.platform.v1`), produced by `build.rs` from the vendored `proto/`.
//!
//! This is codegen output (tonic-prost-build), not hand-audited code, so it
//! opts out of the crate's deny-lints. Higher layers (`transport`, the
//! enrollment flows) wrap these raw stubs in typed, opinionated client logic.
#![allow(clippy::all, clippy::pedantic, clippy::nursery)]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![allow(rust_2018_idioms, unused_qualifications, missing_docs)]

pub mod account {
    pub mod v1 {
        include!(concat!(env!("OUT_DIR"), "/sylva.account.v1.rs"));
    }
}

pub mod platform {
    pub mod v1 {
        include!(concat!(env!("OUT_DIR"), "/sylva.platform.v1.rs"));
    }
}

pub mod machine {
    pub mod v1 {
        include!(concat!(env!("OUT_DIR"), "/sylva.machine.v1.rs"));
    }
}

#[cfg(test)]
mod smoke {
    //! Codegen sanity — the generated message types exist with the expected
    //! fields. No network; construction only.
    #[test]
    fn account_types_are_generated() {
        let _ = super::account::v1::BootstrapRequest::default();
        let _ = super::account::v1::Empty {};
        let device = super::account::v1::DeviceId {
            device_id: "abc".to_string(),
        };
        assert_eq!(device.device_id, "abc");
    }

    #[test]
    fn platform_types_are_generated() {
        let _ = super::platform::v1::Empty {};
        let resource = super::platform::v1::ResourceId {
            id: "r1".to_string(),
        };
        assert_eq!(resource.id, "r1");
    }

    #[test]
    fn machine_types_are_generated() {
        let _ = super::machine::v1::RegisterMachineRequest::default();
        let _ = super::machine::v1::Empty {};
        let cfg = super::machine::v1::MachineConfig {
            location_enabled: true,
        };
        assert!(cfg.location_enabled);
    }
}
