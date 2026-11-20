use super::*;

const SUDOERS_MAIN: &str = "root ALL=(ALL:ALL) ALL\n@includedir /etc/sudoers.d\n";

fn paths_sudoers_d(dir: &Path) -> PathBuf {
    dir.join("etc/sudoers.d")
}

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
    fs::write(dir.join("etc/sudoers"), SUDOERS_MAIN).unwrap();
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
    let sudoers = dir.join("etc/sudoers");
    assert_eq!(
        fs::read_to_string(&sudoers).unwrap(),
        format!("{SUDOERS_MAIN}{BEGIN}\n{SUDOERS}{END}\n")
    );
    assert!(!paths_sudoers_d(&dir).join(SUDOERS_NAME).exists());
    assert!(dir.join("etc/polkit-1/rules.d").join(POLKIT_NAME).exists());
    let doas = fs::read_to_string(dir.join("etc/doas.conf")).unwrap();
    assert!(doas.starts_with("permit persist :wheel\n"));
    assert!(doas.contains("deny alice\n") && !doas.contains("deny nobody"));
    assert_eq!(doas.matches("deny :wheel\n").count(), 1);
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
    assert_eq!(fs::read_to_string(&sudoers).unwrap(), SUDOERS_MAIN);
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
    // The drop-in of earlier releases, and a section left by a crash.
    let drop_in = paths.sudoers_file();
    fs::write(&drop_in, SUDOERS).unwrap();
    let sudoers = dir.join("etc/sudoers");
    fs::write(&sudoers, with_section(SUDOERS_MAIN, SUDOERS)).unwrap();
    let mut h = Hardcore::new(paths, false);
    h.apply(0.0);
    assert!(!drop_in.exists());
    assert_eq!(fs::read_to_string(&sudoers).unwrap(), SUDOERS_MAIN);
    let _ = fs::remove_dir_all(&dir);
}

/// Files in sudoers.d that sort later, and rules after the include, are
/// all read before the end of /etc/sudoers, where the rule goes.
#[test]
fn sudo_rule_comes_last() {
    let (dir, paths) = sandbox();
    let sudoers = dir.join("etc/sudoers");
    let main = "root ALL=(ALL:ALL) ALL\n@includedir /etc/sudoers.d\nalice ALL=(ALL) ALL";
    fs::write(&sudoers, main).unwrap();
    fs::write(
        paths_sudoers_d(&dir).join("zzz-local"),
        "alice ALL=(ALL) ALL\n",
    )
    .unwrap();
    let mut h = Hardcore::new(paths, false);
    h.apply(1000.0);
    let text = fs::read_to_string(&sudoers).unwrap();
    assert!(text.starts_with(&format!("{main}\n{BEGIN}\n")), "{text}");
    assert!(text.ends_with("ALL, !root ALL=(ALL:ALL) !ALL\n# END deepwork hardcore\n"));
    // Checked again later: still once, still last.
    h.apply(2000.0);
    assert_eq!(fs::read_to_string(&sudoers).unwrap(), text);
    h.apply(0.0);
    assert_eq!(fs::read_to_string(&sudoers).unwrap(), format!("{main}\n"));
    let _ = fs::remove_dir_all(&dir);
}

/// Everyone a permit rule lets in is denied, not only regular accounts.
#[test]
fn doas_is_denied_to_everyone_it_permits() {
    let conf = "\
# local rules
permit persist :wheel
permit nopass setenv { PATH=/usr/bin -HOME } bob as root cmd /usr/bin/reboot
permit \"carol\" # a directory account
permit keepenv \\
    dave
permit setenv {FOO} :ops cmd ls
permit nopass root
permit nopass 0
deny eve
";
    assert_eq!(
        doas_permitted(conf),
        [":wheel", "bob", "carol", "dave", ":ops"]
    );

    let (dir, paths) = sandbox();
    let doas = dir.join("etc/doas.conf");
    fs::write(&doas, conf).unwrap();
    let mut h = Hardcore::new(paths, false);
    h.apply(1000.0);
    let text = fs::read_to_string(&doas).unwrap();
    assert!(text.starts_with(conf));
    for who in [":wheel", "bob", "carol", "dave", ":ops", "alice"] {
        assert_eq!(text.matches(&format!("\ndeny {who}\n")).count(), 1, "{who}");
    }
    assert!(!text.contains("deny root"));
    h.apply(0.0);
    assert_eq!(fs::read_to_string(&doas).unwrap(), conf);
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn reads_doas_rules() {
    let rules = doas_rules("permit \"a b\"#x\n\n  deny\tc{d}\\\n e # f \"g\n");
    assert_eq!(
        rules,
        [vec!["permit", "a b"], vec!["deny", "c", "{", "d", "}", "e"]]
    );
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
