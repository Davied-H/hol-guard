//! Read-only resident capture. No approval token or admission allow is issued.

use guard_contracts::{NativeBashCaptureV1, NativeBashSubjectV1};

#[cfg(target_os = "macos")]
#[path = "bash_capture_macos.rs"]
mod platform;

pub(super) fn inspect(request: &NativeBashCaptureV1) -> Result<NativeBashSubjectV1, &'static str> {
    #[cfg(target_os = "macos")]
    return platform::inspect(request);
    #[cfg(not(target_os = "macos"))]
    {
        let _ = request;
        Err("bash_execution_binding_unavailable_platform")
    }
}
