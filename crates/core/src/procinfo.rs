//! Helpers for reading process information.

use crate::model::is_protected_process;

/// Undo systemd unit name escaping (`\x2d` → `-`).
fn unescape(s: &str) -> String {
    let mut out = String::new();
    let mut rest = s;
    while let Some(i) = rest.find("\\x") {
        out.push_str(&rest[..i]);
        let hex = rest
            .get(i + 2..i + 4)
            .and_then(|h| u8::from_str_radix(h, 16).ok());
        match hex {
            Some(b) => {
                out.push(b as char);
                rest = &rest[i + 4..];
            }
            None => {
                out.push_str("\\x");
                rest = &rest[i + 2..];
            }
        }
    }
    out.push_str(rest);
    out
}

/// Extract the launching app's desktop id from a cgroup path, e.g.
/// `app-flatpak-com.discordapp.Discord-1234.scope`,
/// `app-gnome-google\x2dchrome-5678.scope`, `app-org.kde.dolphin@abc.service`.
pub fn app_id_from_cgroup(cgroup: &str) -> Option<String> {
    let unit = cgroup
        .lines()
        .filter_map(|l| l.rsplit('/').next())
        .find(|u| u.starts_with("app-"))?;
    let unit = unit.strip_prefix("app-")?;
    let id = if let Some(stem) = unit.strip_suffix(".scope") {
        let stem = stem
            .strip_prefix("flatpak-")
            .or_else(|| stem.strip_prefix("gnome-"))
            .or_else(|| stem.strip_prefix("kde-"))
            .unwrap_or(stem);
        // drop trailing "-<digits>"
        match stem.rsplit_once('-') {
            Some((head, tail)) if tail.chars().all(|c| c.is_ascii_digit()) => head,
            _ => stem,
        }
    } else {
        let stem = unit.strip_suffix(".service")?;
        stem.split('@').next()?
    };
    let id = unescape(id);
    (!id.is_empty()).then_some(id)
}

/// File name of a Windows path, without `.exe`.
fn exe_stem(path: &str) -> Option<&str> {
    let file = path.rsplit(['\\', '/']).next()?;
    let (stem, ext) = file.rsplit_once('.')?;
    (ext.eq_ignore_ascii_case("exe") && !stem.is_empty()).then_some(stem)
}

/// Block rules for a program or Store app in Windows' Start menu: `target`
/// and `arguments` of its shortcut, and its app user model id. `None` for
/// what isn't an app of its own (documents, uninstallers, web links) or
/// can't be blocked.
pub fn start_menu_rules(target: &str, arguments: &str, id: &str) -> Option<Vec<String>> {
    // Programs that only start others, or run any script.
    const HOSTS: &[&str] = &[
        "control", "cscript", "hh", "java", "javaw", "mmc", "mshta", "node", "perl", "py",
        "python", "pythonw", "pyw", "ruby", "wscript", "wsl", "wslg",
    ];
    // Browsers' starters for installed web apps, which run in the browser.
    const WEB_APPS: &[&str] = &[
        "brave_proxy",
        "chrome_proxy",
        "chrome_pwa_launcher",
        "msedge_proxy",
        "pwahelper",
        "vivaldi_proxy",
    ];
    // Too common to tell programs apart by.
    const GENERIC: &[&str] = &[
        "app", "client", "game", "launch", "launcher", "main", "start",
    ];

    if target.is_empty() {
        // Store apps: PackageFamilyName!App.
        let (family, app) = id.split_once('!')?;
        let (name, publisher) = family.rsplit_once('_')?;
        let ok = publisher.len() == 13 && !name.is_empty() && !app.is_empty();
        return (ok && !family.contains('\\')).then(|| vec![family.to_string()]);
    }
    let stem = exe_stem(target)?;
    let lower = stem.to_lowercase();
    // Squirrel: Update.exe --processStart Discord.exe.
    if lower == "update" || lower == "squirrel" {
        let mut args = arguments.split_whitespace();
        args.find(|a| a.eq_ignore_ascii_case("--processStart"))?;
        let started = args.next()?.trim_matches('"');
        return exe_stem(started).map(|s| vec![s.to_string()]);
    }
    let uninstaller = lower.starts_with("unins") || lower.contains("uninstall");
    if uninstaller
        || HOSTS.contains(&lower.as_str())
        || WEB_APPS.contains(&lower.as_str())
        || is_protected_process(stem)
        || lower.starts_with("python")
    {
        return None;
    }
    if GENERIC.contains(&lower.as_str()) {
        return Some(vec![target.to_string()]);
    }
    Some(vec![stem.to_string()])
}

#[cfg(test)]
mod tests;
