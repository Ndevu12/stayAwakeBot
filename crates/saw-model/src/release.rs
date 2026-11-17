//! The saw release this build belongs to.

/// The release this build belongs to, or `0+unknown` for a build made without one.
pub const RELEASE: &str = match option_env!("SAW_RELEASE") {
    Some(release) if !release.is_empty() => release,
    _ => "0+unknown",
};
