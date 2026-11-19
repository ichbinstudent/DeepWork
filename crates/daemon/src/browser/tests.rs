use super::*;

#[test]
fn firefox_merge_preserves_existing() {
    let orig = json!({"policies": {"DisableTelemetry": true, "WebsiteFilter": {"Block": ["*://bad.example/*"]}}});
    let d = ["reddit.com".to_string()];
    let merged = firefox_policy(&orig, &orig, &d);
    assert_eq!(
        merged.pointer("/policies/DisableTelemetry"),
        Some(&json!(true))
    );
    let block = merged
        .pointer("/policies/WebsiteFilter/Block")
        .unwrap()
        .as_array()
        .unwrap();
    assert_eq!(block.len(), 3);
    assert_eq!(
        merged.pointer("/policies/DNSOverHTTPS/Enabled"),
        Some(&json!(false))
    );
    // Nothing blocked: the original, encrypted DNS included.
    assert_eq!(firefox_policy(&merged, &orig, &[]), orig);
    let own_doh = json!({"policies": {"DNSOverHTTPS": {"Enabled": true}}});
    assert_eq!(firefox_policy(&own_doh, &own_doh, &[]), own_doh);
}

/// Firefox's file is the user's again as soon as nothing is blocked.
#[test]
fn firefox_policies_are_restored_when_idle() {
    let root = std::env::temp_dir().join(format!("dw-firefox-{}", std::process::id()));
    let _ = fs::remove_dir_all(&root);
    let p = Policies {
        layout: Layout {
            chromium: &[],
            chromium_store: None,
            firefox: Some(("/etc/firefox/policies/policies.json", &[])),
        },
        root: root.clone(),
        state_dir: root.join("state"),
        sandbox: true,
    };
    fs::create_dir_all(&p.state_dir).unwrap();
    let file = root.join("etc/firefox/policies/policies.json");
    p.apply(&[]).unwrap();
    assert!(!file.exists(), "nothing written while idle");
    p.apply(&["reddit.com".to_string()]).unwrap();
    assert!(fs::read_to_string(&file).unwrap().contains("DNSOverHTTPS"));
    p.apply(&[]).unwrap();
    assert!(!file.exists(), "no file before, none after");

    let mine = r#"{"policies": {"DisableTelemetry": true}}"#;
    fs::write(&file, mine).unwrap();
    p.apply(&["reddit.com".to_string()]).unwrap();
    p.apply(&[]).unwrap();
    assert_eq!(fs::read_to_string(&file).unwrap(), mine);

    // Policies that someone changes during a block are kept: while it runs
    // (here when its websites change) and when it ends.
    let read = || serde_json::from_str::<Value>(&fs::read_to_string(&file).unwrap()).unwrap();
    p.apply(&["reddit.com".to_string()]).unwrap();
    let mut changed = read();
    changed["policies"]["DisableTelemetry"] = json!(false);
    changed["policies"]["BlockAboutConfig"] = json!(true);
    fs::write(&file, changed.to_string()).unwrap();
    p.apply(&["reddit.com".to_string(), "youtube.com".to_string()])
        .unwrap();
    let during = read();
    assert_eq!(during["policies"]["BlockAboutConfig"], json!(true));
    assert_eq!(during["policies"]["DisableTelemetry"], json!(false));
    assert_eq!(
        during["policies"]["WebsiteFilter"]["Block"]
            .as_array()
            .unwrap()
            .len(),
        4
    );
    p.apply(&[]).unwrap();
    assert_eq!(
        read(),
        json!({"policies": {"DisableTelemetry": false, "BlockAboutConfig": true}})
    );

    // A file that isn't JSON (someone is editing it) is left alone.
    p.apply(&["reddit.com".to_string()]).unwrap();
    fs::write(&file, "{ not json").unwrap();
    assert!(p.apply(&["youtube.com".to_string()]).is_err());
    p.apply(&[]).unwrap();
    assert_eq!(fs::read_to_string(&file).unwrap(), "{ not json");
    // Once it's valid again, our settings come out.
    fs::write(&file, mine).unwrap();
    p.apply(&[]).unwrap();
    assert_eq!(read(), json!({"policies": {"DisableTelemetry": true}}));
    let _ = fs::remove_dir_all(&root);
}

/// Without a file before, the file of policies added during a block stays.
#[test]
fn firefox_keeps_a_file_others_filled() {
    let current = json!({"policies": {
        "DNSOverHTTPS": {"Enabled": false, "Locked": true},
        "WebsiteFilter": {"Block": ["*://reddit.com/*"]},
        "DisableTelemetry": true,
    }});
    assert_eq!(
        firefox_policy(&current, &Value::Null, &[]),
        json!({"policies": {"DisableTelemetry": true}})
    );
}

#[test]
fn chromium_keeps_the_first_domains() {
    let mut d = vec!["reddit.com".to_string()];
    d.extend((0..CHROMIUM_MAX_ENTRIES).map(|i| format!("a{i:04}.example")));
    let list = chromium_policy(&d)["URLBlocklist"]
        .as_array()
        .unwrap()
        .clone();
    assert_eq!(list.len(), CHROMIUM_MAX_ENTRIES);
    assert!(list.contains(&json!("reddit.com")));
    assert!(!list.contains(&json!("a0999.example")));
}

#[test]
fn sandbox_paths_stay_inside() {
    let p = Policies {
        layout: Layout {
            chromium: &[],
            chromium_store: None,
            firefox: None,
        },
        root: "/sb".into(),
        state_dir: "/sb/state".into(),
        sandbox: true,
    };
    assert_eq!(
        p.path("/etc/firefox/p.json"),
        PathBuf::from("/sb/etc/firefox/p.json")
    );
    assert_eq!(
        p.path(r"C:\Program Files\Mozilla Firefox\distribution\policies.json"),
        PathBuf::from(r"/sb/Program Files\Mozilla Firefox\distribution\policies.json")
    );
}

#[test]
fn firefox_from_nothing() {
    let merged = firefox_policy(&Value::Null, &Value::Null, &[]);
    assert!(merged.pointer("/policies/WebsiteFilter").is_none());
    assert!(merged.pointer("/policies/DNSOverHTTPS").is_none());
}
