use super::*;

fn sandbox() -> (PathBuf, Paths) {
    let dir = std::env::temp_dir().join(format!(
        "deepwork-hardcore-{}-{:?}",
        std::process::id(),
        std::thread::current().id()
    ));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(dir.join("etc/sudoers.d")).unwrap();
    fs::create_dir_all(dir.join("etc/polkit-1/rules.d")).unwrap();
    fs::create_dir_all(dir.join("state")).unwrap();
    fs::write(
        dir.join("etc/sudoers"),
        "root ALL=(ALL:ALL) ALL\n@includedir /etc/sudoers.d\n",
    )
    .unwrap();
    fs::write(dir.join("etc/doas.conf"), "permit persist :wheel\n").unwrap();
    fs::write(
        dir.join("etc/passwd"),
        "root:x:0:0::/root:/bin/bash\nalice:x:1000:1000::/home/alice:/bin/bash\n\
         nobody:x:65534:65534::/:/usr/bin/nologin\n",
    )
    .unwrap();
    let paths = Paths::new(&dir, &dir.join("state"));
    (dir, paths)
}

#[test]
fn engage_and_release() {
    let (dir, paths) = sandbox();
    let mut h = Hardcore::new(paths, false);
    h.apply(1000.0);
    assert!(h.warnings.is_empty(), "{:?}", h.warnings);
    let sudoers = dir.join("etc/sudoers.d").join(SUDOERS_NAME);
    assert_eq!(fs::read_to_string(&sudoers).unwrap(), SUDOERS);
    assert!(dir.join("etc/polkit-1/rules.d").join(POLKIT_NAME).exists());
    let doas = fs::read_to_string(dir.join("etc/doas.conf")).unwrap();
    assert!(doas.starts_with("permit persist :wheel\n"));
    assert!(doas.contains("deny alice\n") && !doas.contains("deny nobody"));
    let script = fs::read_to_string(dir.join("state/hardcore-release.sh")).unwrap();
    assert!(script.contains("-ge 1060 ]"));
    assert!(
        dir.join("etc/systemd/system/deepwork-hardcore-release.timer")
            .exists()
    );

    // A later end only moves the safety net's deadline.
    h.apply(2000.0);
    let script = fs::read_to_string(dir.join("state/hardcore-release.sh")).unwrap();
    assert!(script.contains("-ge 2060 ]"));

    h.apply(0.0);
    assert!(!sudoers.exists());
    assert!(!dir.join("etc/polkit-1/rules.d").join(POLKIT_NAME).exists());
    assert_eq!(
        fs::read_to_string(dir.join("etc/doas.conf")).unwrap(),
        "permit persist :wheel\n"
    );
    assert!(
        !dir.join("etc/systemd/system/deepwork-hardcore-release.timer")
            .exists()
    );
    assert!(!dir.join("state/hardcore-release.sh").exists());
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn startup_cleans_up_leftovers() {
    let (dir, paths) = sandbox();
    let sudoers = paths.sudoers_file();
    fs::write(&sudoers, SUDOERS).unwrap();
    let mut h = Hardcore::new(paths, false);
    h.apply(0.0);
    assert!(!sudoers.exists());
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn warns_when_sudo_ignores_the_drop_in() {
    let (dir, paths) = sandbox();
    fs::write(dir.join("etc/sudoers"), "root ALL=(ALL:ALL) ALL\n").unwrap();
    let mut h = Hardcore::new(paths, false);
    h.apply(1000.0);
    assert_eq!(h.warnings.len(), 1);
    assert!(h.warnings[0].starts_with("sudo:"));
    h.apply(0.0);
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn root_password_detection() {
    use RootPassword::*;
    assert_eq!(root_password("root:$6$abc:19000:0:::::\n"), Set);
    assert_eq!(root_password("root::19000::::::\n"), Empty);
    assert_eq!(root_password("root:!$6$abc:19000::::::\n"), Locked);
    assert_eq!(root_password("root:*:19000::::::\n"), Locked);
    assert_eq!(root_password("bin:x:1::::::\n"), Locked);
}
