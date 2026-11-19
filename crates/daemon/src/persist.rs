//! Loading the state file (`state.json`): blocks, locks, schedules,
//! statistics and settings.

use std::fs;
use std::path::{Path, PathBuf};

use crate::state::{Persisted, STATE_FORMAT};

/// The copy of the last state that loaded fine, taken at every start.
fn backup(path: &Path) -> PathBuf {
    path.with_extension("json.bak")
}

fn read(path: &Path) -> Option<Result<Persisted, serde_json::Error>> {
    fs::read_to_string(path)
        .ok()
        .map(|s| serde_json::from_str(&s))
}

/// Load the state. A missing file means a fresh start. A corrupt one is
/// kept as `state.json.corrupt` and the backup from the last start is used
/// instead, so blocks and locks aren't lost. State from a newer release is
/// refused rather than overwritten.
pub fn load(path: &Path) -> Result<Persisted, String> {
    let state = match read(path) {
        None => Persisted::default(),
        Some(Ok(state)) => {
            let _ = fs::copy(path, backup(path));
            state
        }
        Some(Err(e)) => {
            eprintln!(
                "deepwork: {} is corrupt ({e}); keeping a copy",
                path.display()
            );
            let _ = fs::copy(path, path.with_extension("json.corrupt"));
            match read(&backup(path)) {
                Some(Ok(state)) => {
                    eprintln!("deepwork: using the state from the last start instead");
                    state
                }
                _ => {
                    eprintln!("deepwork: no usable backup either; starting without blocks");
                    Persisted::default()
                }
            }
        }
    };
    if state.format > STATE_FORMAT {
        return Err(format!(
            "{} was written by a newer version of DeepWork (state format {}, this version \
             reads up to {STATE_FORMAT}). Install that version again, or move the file away \
             to start over.",
            path.display(),
            state.format
        ));
    }
    Ok(state)
}

#[cfg(test)]
mod tests;
