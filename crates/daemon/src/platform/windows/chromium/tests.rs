use super::*;

fn store(root: &str, dir: &std::path::Path) -> RegistryPolicies {
    RegistryPolicies {
        hive: Hive::User,
        keys: vec![format!(r"{root}\Google\Chrome")],
        backup: dir.join("chromium-registry.orig.json"),
    }
}

fn domains(d: &[&str]) -> Vec<String> {
    d.iter().map(|s| s.to_string()).collect()
}

#[test]
fn registry_policies_round_trip() {
    let root = format!(r"Software\DeepWorkTest{}", std::process::id());
    let dir = std::env::temp_dir().join(format!("deepwork-reg-{}", std::process::id()));
    fs::create_dir_all(&dir).unwrap();
    let hkcu = Hive::User.hkey();
    let chrome = format!(r"{root}\Google\Chrome");

    // A browser that already has policies of its own.
    let key = Key::create(hkcu, &chrome).unwrap();
    key.set_sz("DnsOverHttpsMode", "automatic").unwrap();
    key.write_list("URLBlocklist", &["example.net".into()])
        .unwrap();
    let s = store(&root, &dir);
    s.apply(&domains(&["reddit.com"])).unwrap();
    assert_eq!(key.get("DnsOverHttpsMode"), Some(Saved::Sz("off".into())));
    assert_eq!(key.get("BuiltInDnsClientEnabled"), Some(Saved::Dword(0)));
    assert_eq!(
        key.read_list("URLBlocklist").unwrap(),
        ["example.net", "reddit.com"]
    );
    // A second block keeps the original entries, not the first block's.
    s.apply(&domains(&["youtube.com"])).unwrap();
    assert_eq!(
        key.read_list("URLBlocklist").unwrap(),
        ["example.net", "youtube.com"]
    );
    s.apply(&[]).unwrap();
    assert_eq!(
        key.get("DnsOverHttpsMode"),
        Some(Saved::Sz("automatic".into()))
    );
    assert_eq!(key.get("BuiltInDnsClientEnabled"), None);
    assert_eq!(key.read_list("URLBlocklist").unwrap(), ["example.net"]);
    assert!(!s.backup.exists());
    drop(key);

    // A browser without policies: everything we created goes away.
    let root2 = format!("{root}-new");
    let s = store(&root2, &dir);
    s.apply(&domains(&["reddit.com"])).unwrap();
    assert!(Key::open(hkcu, &format!(r"{root2}\Google\Chrome"), false).is_some());
    s.apply(&[]).unwrap();
    assert!(Key::open(hkcu, &root2, false).is_none());

    // Policies somebody else set meanwhile stay where they are.
    s.apply(&domains(&["reddit.com"])).unwrap();
    let chrome2 = format!(r"{root2}\Google\Chrome");
    Key::open(hkcu, &chrome2, true)
        .unwrap()
        .set_sz("HomepageLocation", "https://example.org")
        .unwrap();
    s.apply(&[]).unwrap();
    let kept = Key::open(hkcu, &chrome2, false).expect("key with foreign values kept");
    assert_eq!(
        kept.get("HomepageLocation"),
        Some(Saved::Sz("https://example.org".into()))
    );
    assert_eq!(kept.get("DnsOverHttpsMode"), None);
    assert!(kept.read_list("URLBlocklist").is_none());
    drop(kept);
    // SAFETY: valid path.
    unsafe { RegDeleteTreeW(hkcu, wide(&root2).as_ptr()) };
    unsafe { RegDeleteKeyExW(hkcu, wide(&root2).as_ptr(), KEY_WOW64_64KEY, 0) };

    // SAFETY: valid path.
    unsafe { RegDeleteTreeW(hkcu, wide(&root).as_ptr()) };
    unsafe { RegDeleteKeyExW(hkcu, wide(&root).as_ptr(), KEY_WOW64_64KEY, 0) };
    let _ = fs::remove_dir_all(dir);
}
