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
