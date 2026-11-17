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
    /// Block these domains; an empty set restores what was there before.
    fn apply(&self, domains: &BTreeSet<String>) -> std::io::Result<()>;
}

/// Where browsers look for policies on an OS. Paths are absolute.
pub struct Layout {
    pub chromium: &'static [ChromiumFlavor],
    pub chromium_store: Option<Box<dyn PolicyStore>>,
    /// Firefox's `policies.json` and its install markers.
    pub firefox: Option<(&'static str, &'static [&'static str])>,
}

pub fn chromium_policy(domains: &BTreeSet<String>) -> Value {
    json!({
        "DnsOverHttpsMode": "off",
        "BuiltInDnsClientEnabled": false,
        // Chromium ignores entries beyond 1000; /etc/hosts still covers the rest.
        "URLBlocklist": domains.iter().take(1000).collect::<Vec<_>>(),
    })
}

/// Merge our settings into an existing Firefox `policies.json` value.
/// `original` is the file as it was before DeepWork touched it.
pub fn firefox_policy(original: &Value, domains: &BTreeSet<String>) -> Value {
    let mut root = original.as_object().cloned().unwrap_or_default();
    let mut policies = root
        .get("policies")
        .and_then(Value::as_object)
        .cloned()
        .unwrap_or_else(Map::new);
    policies.insert(
        "DNSOverHTTPS".into(),
        json!({ "Enabled": false, "Locked": true }),
    );
    if domains.is_empty() {
        match original.pointer("/policies/WebsiteFilter") {
            Some(v) => policies.insert("WebsiteFilter".into(), v.clone()),
            None => policies.remove("WebsiteFilter"),
        };
    } else {
        let mut block: Vec<Value> = original
            .pointer("/policies/WebsiteFilter/Block")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default();
        for d in domains {
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

    pub fn apply(&self, domains: &BTreeSet<String>) -> std::io::Result<()> {
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
        if let Some((policy, markers)) = self.layout.firefox
            && (self.installed(markers) || self.path(policy).exists())
        {
            self.apply_firefox(policy, domains)?;
        }
        if let Some(store) = &self.layout.chromium_store {
            store.apply(domains)?;
        }
        Ok(())
    }

    fn firefox_backup(&self) -> PathBuf {
        self.state_dir.join("firefox-policies.orig.json")
    }

    fn apply_firefox(&self, policy: &str, domains: &BTreeSet<String>) -> std::io::Result<()> {
        let file = self.path(policy);
        let backup = self.firefox_backup();
        if !backup.exists() {
            // Remember what was there before (or that nothing was).
            let original = fs::read_to_string(&file).unwrap_or_else(|_| "null".into());
            crate::write_atomic(&backup, original.as_bytes(), 0o600)?;
        }
        let original: Value =
            serde_json::from_str(&fs::read_to_string(&backup)?).unwrap_or(Value::Null);
        let new = serde_json::to_string_pretty(&firefox_policy(&original, domains))?;
        if fs::read_to_string(&file).ok().as_deref() != Some(new.as_str()) {
            fs::create_dir_all(file.parent().unwrap())?;
            crate::write_atomic(&file, new.as_bytes(), 0o644)?;
        }
        Ok(())
    }

    /// Undo everything (used on uninstall).
    pub fn cleanup(&self) -> std::io::Result<()> {
        for flavor in self.layout.chromium {
            let _ = fs::remove_file(self.path(flavor.dir).join(POLICY_FILE));
        }
        if let Some(store) = &self.layout.chromium_store {
            store.apply(&BTreeSet::new())?;
        }
        let backup = self.firefox_backup();
        if let Some((policy, _)) = self.layout.firefox
            && let Ok(orig) = fs::read_to_string(&backup)
        {
            let file = self.path(policy);
            if orig.trim() == "null" {
                let _ = fs::remove_file(&file);
            } else {
                crate::write_atomic(&file, orig.as_bytes(), 0o644)?;
            }
            let _ = fs::remove_file(backup);
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
        let d: BTreeSet<String> = ["reddit.com".to_string()].into();
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
        let cleared = firefox_policy(&orig, &BTreeSet::new());
        assert_eq!(
            cleared.pointer("/policies/WebsiteFilter"),
            orig.pointer("/policies/WebsiteFilter")
        );
        assert_eq!(
            cleared.pointer("/policies/DNSOverHTTPS/Enabled"),
            Some(&json!(false))
        );
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
        let merged = firefox_policy(&Value::Null, &BTreeSet::new());
        assert!(merged.pointer("/policies/WebsiteFilter").is_none());
    }
}
