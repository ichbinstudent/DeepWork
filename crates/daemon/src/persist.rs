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
mod tests {
    use super::*;
    use deepwork_core::model::LockKind;

    fn temp(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("dw-persist-{}-{name}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        dir.join("state.json")
    }

    /// State files written by every release so far still load. Add the file
    /// of each new format here.
    #[test]
    fn loads_state_from_earlier_releases() {
        let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/data");
        // Load a copy: loading makes a backup next to the file.
        let copy = |name: &str| {
            let path = temp(name);
            fs::copy(dir.join(name), &path).unwrap();
            path
        };
        let v010 = load(&copy("state-0.1.0.json")).unwrap();
        assert_eq!(v010.blocks.len(), 2);
        let social = v010
            .blocks
            .iter()
            .find(|b| b.config.name == "Social")
            .unwrap();
        assert_eq!(social.config.lock, LockKind::Strict);
        assert_eq!(social.config.lists, ["social"]);
        assert!(social.rt.session_until > 0.0);
        assert!(!v010.stats.is_empty());
    }

    #[test]
    fn corrupt_state_falls_back_to_the_backup() {
        let path = temp("corrupt");
        fs::write(&path, r#"{"blocks": [], "frozen_until": 5.0}"#).unwrap();
        assert_eq!(load(&path).unwrap().frozen_until, 5.0); // also makes the backup
        fs::write(&path, "{ broken").unwrap();
        assert_eq!(load(&path).unwrap().frozen_until, 5.0);
        assert!(path.with_extension("json.corrupt").exists());
    }

    #[test]
    fn refuses_state_from_a_newer_release() {
        let path = temp("newer");
        fs::write(&path, format!(r#"{{"format": {}}}"#, STATE_FORMAT + 1)).unwrap();
        assert!(load(&path).unwrap_err().contains("newer version"));
        assert!(load(&temp("missing")).unwrap().blocks.is_empty());
    }
}
