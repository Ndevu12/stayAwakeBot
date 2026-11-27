//! What differs between the systems the folder guard and the git stand-in run on: how a file is
//! named and found, who owns a folder, and how a program runs in place of this one. Unix and Windows
//! each give the same names with the same meaning.

#[cfg(unix)]
mod unix;
#[cfg(unix)]
use unix as this_system;

#[cfg(windows)]
mod windows;
#[cfg(windows)]
use windows as this_system;

pub use this_system::{
    belongs_to_this_user, create_private_folder, environment_key, file_id, home_folder, name_bytes, place_link, program_file_names,
    run_in_place_of_this_process, same_file_name, NULL_DEVICE, PATH_LIST_SEPARATOR, SHELL_FILES_TURN_ON_TERMINALS,
};
