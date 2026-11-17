//! The saw release this build belongs to.
//!
//! The release exists only as the git tag. A release build passes it in through the
//! `SAW_RELEASE` environment variable; nothing in the source tree carries it. A build without
//! it reports `0+unknown`, as the Python package does from a source tree.

/// The release this build belongs to, or `0+unknown` for a build made without one.
pub const RELEASE: &str = match option_env!("SAW_RELEASE") {
    Some(release) if !release.is_empty() => release,
    _ => "0+unknown",
};
