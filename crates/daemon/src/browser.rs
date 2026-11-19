//! Browser enterprise policies.
//!
//! Chromium-based browsers re-read their policies while running, so a URL
//! blocklist takes effect immediately, covers all subdomains and shows a
//! proper "blocked" page. Policies also turn off DNS-over-HTTPS so browsers
//! can't route around the hosts file. Firefox reads its policies at start-up.
//!
//! The policy contents are the same everywhere; the platform supplies the
//! file locations as a [`Layout`].

use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

use serde_json::{Map, Value, json};

pub const POLICY_FILE: &str = "deepwork.json";

/// A Chromium-based browser that reads JSON policy files from a directory.
pub struct ChromiumFlavor {
    pub dir: &'static str,
    /// Files whose presence means the browser is installed.
    pub markers: &'static [&'static str],
}

/// Chromium policies kept somewhere other than JSON files (the Windows
/// registry), with the same contents as [`chromium_policy`].
pub trait PolicyStore: Send {
    /// Block these domains (most important first); none restores what was
    /// there before.
    fn apply(&self, domains: &[String]) -> std::io::Result<()>;
}

/// Where browsers look for policies on an OS. Paths are absolute.
pub struct Layout {
    pub chromium: &'static [ChromiumFlavor],
    pub chromium_store: Option<Box<dyn PolicyStore>>,
    /// Firefox's `policies.json` and its install markers.
    pub firefox: Option<(&'static str, &'static [&'static str])>,
}

/// Chromium reads at most this many entries of `URLBlocklist`.
pub const CHROMIUM_MAX_ENTRIES: usize = 1000;

/// The policy for `domains`, which come most important first: Chromium
/// ignores entries beyond [`CHROMIUM_MAX_ENTRIES`], so domains added later
/// can't push out those that were blocked already. The hosts file still
/// covers the rest.
pub fn chromium_policy(domains: &[String]) -> Value {
    let first: BTreeSet<&String> = domains.iter().take(CHROMIUM_MAX_ENTRIES).collect();
    json!({
        "DnsOverHttpsMode": "off",
        "BuiltInDnsClientEnabled": false,
        "URLBlocklist": first,
    })
}

/// Merge our settings into an existing Firefox `policies.json` value.
/// `original` is the file as it was before DeepWork touched it. Without
/// domains it is the original again: encrypted DNS is only turned off while
/// websites are blocked.
pub fn firefox_policy(original: &Value, domains: &[String]) -> Value {
    let mut root = original.as_object().cloned().unwrap_or_default();
    let mut policies = root
        .get("policies")
        .and_then(Value::as_object)
        .cloned()
        .unwrap_or_else(Map::new);
    if domains.is_empty() {
        for name in ["DNSOverHTTPS", "WebsiteFilter"] {
            match original.pointer(&format!("/policies/{name}")) {
                Some(v) => policies.insert(name.into(), v.clone()),
                None => policies.remove(name),
            };
        }
    } else {
        policies.insert(
            "DNSOverHTTPS".into(),
            json!({ "Enabled": false, "Locked": true }),
        );
        let mut block: Vec<Value> = original
            .pointer("/policies/WebsiteFilter/Block")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default();
        for d in domains.iter().collect::<BTreeSet<_>>() {
            block.push(json!(format!("*://{d}/*")));
            block.push(json!(format!("*://*.{d}/*")));
        }
        let mut filter = original
            .pointer("/policies/WebsiteFilter")
            .and_then(Value::as_object)
            .cloned()
            .unwrap_or_default();
        filter.insert("Block".into(), Value::Array(block));
        policies.insert("WebsiteFilter".into(), Value::Object(filter));
    }
    root.insert("policies".into(), Value::Object(policies));
    Value::Object(root)
}

/// Writes policy files, under `root` in the sandbox.
pub struct Policies {
    pub layout: Layout,
    pub root: PathBuf,
    pub state_dir: PathBuf,
    /// Sandbox: files go under `root` and every browser counts as installed.
    pub sandbox: bool,
}

impl Policies {
    fn path(&self, abs: &str) -> PathBuf {
        if !self.sandbox {
            return PathBuf::from(abs);
        }
        // "/etc/x" and "C:\\Program Files\\x" both end up below root.
        let rel = abs
            .split_once(":\\")
            .map_or(abs, |(_, rest)| rest)
            .trim_start_matches(['/', '\\']);
        self.root.join(rel)
    }

    fn installed(&self, markers: &[&str]) -> bool {
        self.sandbox || markers.iter().any(|m| Path::new(m).exists())
    }

    /// Block `domains` (most important first); none takes our policies out.
    pub fn apply(&self, domains: &[String]) -> std::io::Result<()> {
        for flavor in self.layout.chromium {
            let dir = self.path(flavor.dir);
            let file = dir.join(POLICY_FILE);
            if domains.is_empty() {
                if file.exists() {
                    fs::remove_file(&file)?;
                }
                continue;
            }
            if !self.installed(flavor.markers) && !dir.exists() {
                continue;
            }
            fs::create_dir_all(&dir)?;
            crate::write_atomic(
                &file,
                serde_json::to_string_pretty(&chromium_policy(domains))?.as_bytes(),
                0o644,
            )?;
        }
        if let Some((policy, markers)) = self.layout.firefox {
            if domains.is_empty() {
                self.restore_firefox(policy)?;
            } else if self.installed(markers) || self.path(policy).exists() {
                self.apply_firefox(policy, domains)?;
            }
        }
        if let Some(store) = &self.layout.chromium_store {
            store.apply(domains)?;
        }
        Ok(())
    }

    fn firefox_backup(&self) -> PathBuf {
        self.state_dir.join("firefox-policies.orig.json")
    }

    fn apply_firefox(&self, policy: &str, domains: &[String]) -> std::io::Result<()> {
        let file = self.path(policy);
        let dir = file.parent().unwrap_or(Path::new("/"));
        // Firefox can be installed where users may write (e.g. an app bundle
        // a user copied). The service doesn't write there: a link could send
        // the file anywhere.
        if !self.sandbox && !crate::admin_only(dir) {
            eprintln!(
                "deepwork: not writing Firefox's policies: {} can be changed by \
                 non-administrators",
                dir.display()
            );
            return Ok(());
        }
        let backup = self.firefox_backup();
        if !backup.exists() {
            // Remember what was there before (or that nothing was).
            let original = crate::read_managed(&file).unwrap_or_else(|_| "null".into());
            crate::write_atomic(&backup, original.as_bytes(), 0o600)?;
        }
        let original: Value =
            serde_json::from_str(&fs::read_to_string(&backup)?).unwrap_or(Value::Null);
        let new = serde_json::to_string_pretty(&firefox_policy(&original, domains))?;
        if crate::read_managed(&file).ok().as_deref() != Some(new.as_str()) {
            fs::create_dir_all(dir)?;
            crate::write_atomic(&file, new.as_bytes(), 0o644)?;
        }
        Ok(())
    }

    /// Put Firefox's `policies.json` back the way it was before DeepWork, so
    /// nothing of ours (such as encrypted DNS being off) stays while no
    /// websites are blocked.
    fn restore_firefox(&self, policy: &str) -> std::io::Result<()> {
        let backup = self.firefox_backup();
        let Ok(orig) = fs::read_to_string(&backup) else {
            return Ok(());
        };
        let file = self.path(policy);
        if orig.trim() == "null" {
            match fs::remove_file(&file) {
                Err(e) if e.kind() != std::io::ErrorKind::NotFound => return Err(e),
                _ => {}
            }
        } else {
            crate::write_atomic(&file, orig.as_bytes(), 0o644)?;
        }
        fs::remove_file(backup)
    }

    /// Undo everything (used on uninstall).
    pub fn cleanup(&self) -> std::io::Result<()> {
        for flavor in self.layout.chromium {
            let _ = fs::remove_file(self.path(flavor.dir).join(POLICY_FILE));
        }
        if let Some(store) = &self.layout.chromium_store {
            store.apply(&[])?;
        }
        if let Some((policy, _)) = self.layout.firefox {
            self.restore_firefox(policy)?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn firefox_merge_preserves_existing() {
        let orig = json!({"policies": {"DisableTelemetry": true, "WebsiteFilter": {"Block": ["*://bad.example/*"]}}});
        let d = ["reddit.com".to_string()];
        let merged = firefox_policy(&orig, &d);
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
        assert_eq!(firefox_policy(&orig, &[]), orig);
        let own_doh = json!({"policies": {"DNSOverHTTPS": {"Enabled": true}}});
        assert_eq!(firefox_policy(&own_doh, &[]), own_doh);
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
        let _ = fs::remove_dir_all(&root);
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
        let merged = firefox_policy(&Value::Null, &[]);
        assert!(merged.pointer("/policies/WebsiteFilter").is_none());
        assert!(merged.pointer("/policies/DNSOverHTTPS").is_none());
    }
}
