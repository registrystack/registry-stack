mod legacy;

pub use legacy::{
    load_startup_config, load_startup_config_with_options, render_governed_runtime_target_json,
    run, sidecar_router, verify_governed_bundle_report_json, SidecarConfig, SidecarError,
};
