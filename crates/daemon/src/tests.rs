use super::*;

#[test]
fn allow_user_keeps_other_settings() {
    let dir = std::env::temp_dir().join(format!("dw-allow-{}", std::process::id()));
    let path = dir.join("config.json");
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).unwrap();
    fs::write(&path, r#"{"allowed_users": [1000], "other": true}"#).unwrap();
    let me = if cfg!(windows) {
        "S-1-5-21-1-2-3-1001"
    } else {
        "1001"
    };
    allow_user(&path, me).unwrap();
    allow_user(&path, me).unwrap(); // only once
    let v: serde_json::Value = serde_json::from_str(&fs::read_to_string(&path).unwrap()).unwrap();
    assert_eq!(v["other"], true);
    let list = v["allowed_users"].as_array().unwrap();
    if cfg!(windows) {
        // Bare numbers (old style) are dropped on Windows.
        assert_eq!(list, &[serde_json::json!(me)]);
        assert!(allow_user(&path, "1001").is_err());
    } else {
        assert_eq!(list, &[serde_json::json!(1000), serde_json::json!(1001)]);
    }
    assert_eq!(allowed_users(&path).len(), list.len());
    // A broken, empty or missing file lets only administrators in.
    fs::write(&path, "{ nope").unwrap();
    assert_eq!(allowed_users(&path), vec![]);
    fs::write(&path, r#"{"allowed_users": []}"#).unwrap();
    assert_eq!(allowed_users(&path), vec![]);
    fs::write(&path, "{}").unwrap();
    assert_eq!(allowed_users(&path), vec![]);
    fs::remove_file(&path).unwrap();
    assert_eq!(allowed_users(&path), vec![]);
    let _ = fs::remove_dir_all(&dir);
}

#[cfg(unix)]
#[test]
fn writes_never_follow_foreign_links() {
    use std::os::unix::fs::symlink;
    let dir = std::env::temp_dir().join(format!("dw-links-{}", std::process::id()));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).unwrap();
    // The test's folder isn't root's, so links in it are not followed.
    assert!(!admin_only(&dir));
    let target = dir.join("target");
    fs::write(&target, "precious").unwrap();

    // A link at the file itself is replaced, the target left alone.
    let file = dir.join("policies.json");
    symlink(&target, &file).unwrap();
    assert!(read_managed(&file).is_err());
    write_atomic(&file, b"{}", 0o644).unwrap();
    assert_eq!(fs::read_to_string(&target).unwrap(), "precious");
    assert!(
        !fs::symlink_metadata(&file)
            .unwrap()
            .file_type()
            .is_symlink()
    );
    assert_eq!(read_managed(&file).unwrap(), "{}");

    // So is a link planted where the temporary file goes.
    let tmp = dir.join(".policies.json.deepwork-tmp");
    symlink(&target, &tmp).unwrap();
    write_atomic(&file, b"[]", 0o644).unwrap();
    assert_eq!(fs::read_to_string(&target).unwrap(), "precious");
    assert_eq!(fs::read_to_string(&file).unwrap(), "[]");
    assert!(!tmp.exists());

    // The in-place fallback doesn't follow links either.
    symlink(&target, dir.join("link")).unwrap();
    assert!(rewrite_in_place(&dir.join("link"), b"x").is_err());
    assert_eq!(fs::read_to_string(&target).unwrap(), "precious");

    // Root's own folders are trusted, also before they exist; /tmp is not.
    assert!(admin_only(Path::new("/")));
    assert!(admin_only(Path::new("/nonexistent-deepwork/x")));
    assert!(!admin_only(Path::new("/tmp")));
    let _ = fs::remove_dir_all(&dir);
}
