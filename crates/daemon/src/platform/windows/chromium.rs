//! Chromium policies in the Windows registry. Chrome, Edge, Brave and
//! Chromium read them from `HKLM\SOFTWARE\Policies\<vendor>` and re-read
//! them when Windows announces a policy refresh (otherwise only every 15
//! minutes), so every change is followed by one. The URL blocklist is
//! enforced inside the browser, so proxy and VPN extensions can't get around
//! it.
//!
//! Whatever was there before is saved on first use and restored when no
//! websites are blocked any more; existing blocklist entries are kept, and
//! keys DeepWork created are only removed when nothing else was put in them.

use std::collections::BTreeMap;
use std::fs;
use std::io;
use std::path::PathBuf;
use std::ptr::{null, null_mut};

use serde::{Deserialize, Serialize};
use serde_json::Value;
use windows_sys::Win32::Foundation::ERROR_SUCCESS;
use windows_sys::Win32::System::GroupPolicy::{RP_FORCE, RefreshPolicyEx};
use windows_sys::Win32::System::Registry::{
    HKEY, HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE, KEY_READ, KEY_WOW64_64KEY, KEY_WRITE, REG_DWORD,
    REG_OPTION_NON_VOLATILE, REG_SZ, RegCloseKey, RegCreateKeyExW, RegDeleteKeyExW, RegDeleteTreeW,
    RegDeleteValueW, RegOpenKeyExW, RegQueryInfoKeyW, RegQueryValueExW, RegSetValueExW,
};

use crate::browser::{PolicyStore, chromium_policy};

/// Policy keys of the Chromium-based browsers that support policies.
pub const BROWSER_KEYS: &[&str] = &[
    r"SOFTWARE\Policies\Google\Chrome",
    r"SOFTWARE\Policies\Microsoft\Edge",
    r"SOFTWARE\Policies\BraveSoftware\Brave",
    r"SOFTWARE\Policies\Chromium",
];

#[derive(Debug, Clone, Copy)]
#[cfg_attr(not(test), allow(dead_code))] // `User` is for tests
pub enum Hive {
    Machine,
    User,
}

impl Hive {
    fn hkey(self) -> HKEY {
        match self {
            Hive::Machine => HKEY_LOCAL_MACHINE,
            Hive::User => HKEY_CURRENT_USER,
        }
    }
}

pub struct RegistryPolicies {
    pub hive: Hive,
    pub keys: Vec<String>,
    /// Where the values from before DeepWork are kept.
    pub backup: PathBuf,
}

/// A registry value as it was before DeepWork changed it.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
enum Saved {
    Missing,
    Sz(String),
    Dword(u32),
    List(Vec<String>),
}

#[derive(Debug, Default, Serialize, Deserialize)]
struct Backup {
    /// Keys that didn't exist before, parents first.
    created: Vec<String>,
    /// Key path → policy name → old value.
    values: BTreeMap<String, BTreeMap<String, Saved>>,
}

impl PolicyStore for RegistryPolicies {
    fn apply(&self, domains: &[String]) -> io::Result<()> {
        let result = self.write(domains);
        if let Hive::Machine = self.hive {
            announce_policy_change();
        }
        result
    }
}

/// Tell running browsers to re-read their policies now. Runs in the
/// background: a policy refresh can take a moment.
fn announce_policy_change() {
    std::thread::spawn(|| {
        // SAFETY: no pointers involved.
        unsafe { RefreshPolicyEx(1, RP_FORCE) };
    });
}

impl RegistryPolicies {
    fn write(&self, domains: &[String]) -> io::Result<()> {
        if domains.is_empty() {
            return self.restore();
        }
        let policy = chromium_policy(domains);
        let Some(policy) = policy.as_object() else {
            return Ok(());
        };
        let backup = match self.read_backup() {
            Some(b) => b,
            None => {
                let b = self.snapshot(policy);
                crate::write_atomic(&self.backup, &serde_json::to_vec_pretty(&b)?, 0o600)?;
                b
            }
        };
        for path in &self.keys {
            let key = Key::create(self.hive.hkey(), path)?;
            for (name, value) in policy {
                match value {
                    Value::String(s) => key.set_sz(name, s)?,
                    Value::Bool(b) => key.set_dword(name, u32::from(*b))?,
                    Value::Array(items) => {
                        let mut list = match backup.values.get(path).and_then(|m| m.get(name)) {
                            Some(Saved::List(l)) => l.clone(),
                            _ => vec![],
                        };
                        for s in items.iter().filter_map(Value::as_str) {
                            if !list.iter().any(|x| x == s) {
                                list.push(s.to_string());
                            }
                        }
                        list.truncate(crate::browser::CHROMIUM_MAX_ENTRIES);
                        key.write_list(name, &list)?;
                    }
                    _ => {}
                }
            }
        }
        Ok(())
    }

    fn read_backup(&self) -> Option<Backup> {
        serde_json::from_str(&fs::read_to_string(&self.backup).ok()?).ok()
    }

    /// Record the current values of everything [`apply`](PolicyStore::apply)
    /// is about to change.
    fn snapshot(&self, policy: &serde_json::Map<String, Value>) -> Backup {
        let mut b = Backup::default();
        for path in &self.keys {
            let parts: Vec<&str> = path.split('\\').collect();
            for n in 1..=parts.len() {
                let p = parts[..n].join("\\");
                if Key::open(self.hive.hkey(), &p, false).is_none() && !b.created.contains(&p) {
                    b.created.push(p);
                }
            }
            let key = Key::open(self.hive.hkey(), path, false);
            let saved = policy
                .iter()
                .map(|(name, value)| {
                    let old = match (&key, value) {
                        (None, _) => None,
                        (Some(k), Value::Array(_)) => k.read_list(name).map(Saved::List),
                        (Some(k), _) => k.get(name),
                    };
                    (name.clone(), old.unwrap_or(Saved::Missing))
                })
                .collect();
            b.values.insert(path.clone(), saved);
        }
        b
    }

    /// Put back what was there before DeepWork.
    fn restore(&self) -> io::Result<()> {
        let Some(b) = self.read_backup() else {
            return Ok(());
        };
        for (path, saved) in &b.values {
            let Some(key) = Key::open(self.hive.hkey(), path, true) else {
                continue;
            };
            for (name, old) in saved {
                match old {
                    Saved::Missing => {
                        key.delete_value(name);
                        key.delete_tree(name);
                    }
                    Saved::Sz(v) => key.set_sz(name, v)?,
                    Saved::Dword(v) => key.set_dword(name, *v)?,
                    Saved::List(l) => key.write_list(name, l)?,
                }
            }
        }
        // Children first. A key that something else (an administrator, other
        // software) has put values or keys into since stays, with them.
        for p in b.created.iter().rev() {
            let empty = Key::open(self.hive.hkey(), p, false).is_some_and(|k| k.is_empty());
            if empty {
                // SAFETY: valid NUL-terminated path.
                unsafe { RegDeleteKeyExW(self.hive.hkey(), wide(p).as_ptr(), KEY_WOW64_64KEY, 0) };
            }
        }
        fs::remove_file(&self.backup)
    }
}

fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain([0]).collect()
}

fn check(code: u32) -> io::Result<()> {
    if code == ERROR_SUCCESS {
        Ok(())
    } else {
        Err(io::Error::from_raw_os_error(code as i32))
    }
}

/// An open registry key, closed on drop.
struct Key(HKEY);

impl Drop for Key {
    fn drop(&mut self) {
        // SAFETY: we own the handle.
        unsafe { RegCloseKey(self.0) };
    }
}

impl Key {
    fn open(parent: HKEY, path: &str, write: bool) -> Option<Key> {
        let sam = KEY_READ | KEY_WOW64_64KEY | if write { KEY_WRITE } else { 0 };
        let mut h: HKEY = null_mut();
        // SAFETY: valid path and out pointer.
        let code = unsafe { RegOpenKeyExW(parent, wide(path).as_ptr(), 0, sam, &mut h) };
        (code == ERROR_SUCCESS).then_some(Key(h))
    }

    fn create(parent: HKEY, path: &str) -> io::Result<Key> {
        let mut h: HKEY = null_mut();
        // SAFETY: valid path and out pointer.
        check(unsafe {
            RegCreateKeyExW(
                parent,
                wide(path).as_ptr(),
                0,
                null(),
                REG_OPTION_NON_VOLATILE,
                KEY_READ | KEY_WRITE | KEY_WOW64_64KEY,
                null(),
                &mut h,
                null_mut(),
            )
        })?;
        Ok(Key(h))
    }

    /// Whether the key has no values and no subkeys.
    fn is_empty(&self) -> bool {
        let (mut subkeys, mut values) = (0u32, 0u32);
        // SAFETY: valid key and out pointers; everything else is optional.
        let code = unsafe {
            RegQueryInfoKeyW(
                self.0,
                null_mut(),
                null_mut(),
                null(),
                &mut subkeys,
                null_mut(),
                null_mut(),
                &mut values,
                null_mut(),
                null_mut(),
                null_mut(),
                null_mut(),
            )
        };
        code == ERROR_SUCCESS && subkeys == 0 && values == 0
    }

    /// A string or DWORD value.
    fn get(&self, name: &str) -> Option<Saved> {
        let name = wide(name);
        let (mut ty, mut len) = (0u32, 0u32);
        // SAFETY: size query with valid out pointers.
        let code = unsafe {
            RegQueryValueExW(self.0, name.as_ptr(), null(), &mut ty, null_mut(), &mut len)
        };
        if code != ERROR_SUCCESS {
            return None;
        }
        let mut buf = vec![0u8; len as usize];
        // SAFETY: `buf` holds `len` bytes.
        let code = unsafe {
            RegQueryValueExW(
                self.0,
                name.as_ptr(),
                null(),
                &mut ty,
                buf.as_mut_ptr(),
                &mut len,
            )
        };
        if code != ERROR_SUCCESS {
            return None;
        }
        buf.truncate(len as usize);
        match ty {
            REG_SZ => {
                let units: Vec<u16> = buf
                    .as_chunks::<2>()
                    .0
                    .iter()
                    .map(|c| u16::from_le_bytes(*c))
                    .collect();
                let s = String::from_utf16_lossy(&units);
                Some(Saved::Sz(s.trim_end_matches('\0').to_string()))
            }
            REG_DWORD if buf.len() == 4 => Some(Saved::Dword(u32::from_le_bytes([
                buf[0], buf[1], buf[2], buf[3],
            ]))),
            _ => None,
        }
    }

    fn set_sz(&self, name: &str, value: &str) -> io::Result<()> {
        let data = wide(value);
        // SAFETY: `data` is a NUL-terminated UTF-16 string of the given size.
        check(unsafe {
            RegSetValueExW(
                self.0,
                wide(name).as_ptr(),
                0,
                REG_SZ,
                data.as_ptr() as *const u8,
                (data.len() * 2) as u32,
            )
        })
    }

    fn set_dword(&self, name: &str, value: u32) -> io::Result<()> {
        // SAFETY: four bytes of data.
        check(unsafe {
            RegSetValueExW(
                self.0,
                wide(name).as_ptr(),
                0,
                REG_DWORD,
                &value as *const u32 as *const u8,
                4,
            )
        })
    }

    fn delete_value(&self, name: &str) {
        // SAFETY: valid name; a missing value is fine.
        unsafe { RegDeleteValueW(self.0, wide(name).as_ptr()) };
    }

    fn delete_tree(&self, name: &str) {
        // SAFETY: valid name; a missing subkey is fine.
        unsafe { RegDeleteTreeW(self.0, wide(name).as_ptr()) };
    }

    /// Chromium list policies are subkeys with values named 1, 2, 3…
    fn read_list(&self, name: &str) -> Option<Vec<String>> {
        let sub = Key::open(self.0, name, false)?;
        let mut out = vec![];
        for i in 1.. {
            match sub.get(&i.to_string()) {
                Some(Saved::Sz(s)) => out.push(s),
                _ => break,
            }
        }
        Some(out)
    }

    fn write_list(&self, name: &str, items: &[String]) -> io::Result<()> {
        self.delete_tree(name);
        let sub = Key::create(self.0, name)?;
        for (i, s) in items.iter().enumerate() {
            sub.set_sz(&(i + 1).to_string(), s)?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
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
}
