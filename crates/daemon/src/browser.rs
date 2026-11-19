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

/// Firefox's `policies.json` value with our settings merged into `current`,
/// the file as it is now. Only `DNSOverHTTPS` and `WebsiteFilter` are ours,
/// built on what `original` (the file before DeepWork touched it) had there.
/// Without domains they are `original`'s again: encrypted DNS is only turned
/// off while websites are blocked. Everything else stays as it is in
/// `current`, so policies that change during a block are kept.
pub fn firefox_policy(current: &Value, original: &Value, domains: &[String]) -> Value {
    let mut root = current.as_object().cloned().unwrap_or_default();
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
        let current = read_policies(&file)?;
        let backup = self.firefox_backup();
        if !backup.exists() {
            // Remember what was there before (or that nothing was).
            let original = match &current {
                Some((text, _)) => text.clone(),
                None => "null".into(),
            };
            crate::write_atomic(&backup, original.as_bytes(), 0o600)?;
        }
        let original: Value =
            serde_json::from_str(&fs::read_to_string(&backup)?).unwrap_or(Value::Null);
        let current = current.map_or(Value::Null, |(_, v)| v);
        let new = firefox_policy(&current, &original, domains);
        if new != current {
            fs::create_dir_all(dir)?;
            crate::write_atomic(&file, serde_json::to_string_pretty(&new)?.as_bytes(), 0o644)?;
        }
        Ok(())
    }

    /// Take our settings out of Firefox's `policies.json` again, so nothing
    /// of ours (such as encrypted DNS being off) stays while no websites are
    /// blocked. What others changed in the meantime stays.
    fn restore_firefox(&self, policy: &str) -> std::io::Result<()> {
        let backup = self.firefox_backup();
        let Ok(orig) = fs::read_to_string(&backup) else {
            return Ok(());
        };
        let original: Value = serde_json::from_str(&orig).unwrap_or(Value::Null);
        let file = self.path(policy);
        let current = match read_policies(&file) {
            // Someone is editing it: try again next time.
            Err(e) if e.kind() == std::io::ErrorKind::InvalidData => {
                eprintln!("deepwork: {e}");
                return Ok(());
            }
            other => other?,
        };
        if let Some((_, current)) = current {
            let restored = firefox_policy(&current, &original, &[]);
            if restored == original {
                // Exactly as before, formatting included.
                crate::write_atomic(&file, orig.as_bytes(), 0o644)?;
            } else if original.is_null() && restored == json!({ "policies": {} }) {
                fs::remove_file(&file)?;
            } else if restored != current {
                crate::write_atomic(
                    &file,
                    serde_json::to_string_pretty(&restored)?.as_bytes(),
                    0o644,
                )?;
            }
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

/// Firefox's `policies.json` as text and value, `None` if there is none. A
/// file that isn't valid JSON is an error: it's left alone rather than
/// replaced.
fn read_policies(file: &Path) -> std::io::Result<Option<(String, Value)>> {
    let text = match crate::read_managed(file) {
        Ok(text) => text,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e),
    };
    match serde_json::from_str(&text) {
        Ok(v) => Ok(Some((text, v))),
        Err(e) => Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!(
                "{} isn't valid JSON ({e}); leaving it alone",
                file.display()
            ),
        )),
    }
}

#[cfg(test)]
mod tests;
