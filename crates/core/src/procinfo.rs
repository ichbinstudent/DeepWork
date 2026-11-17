//! Helpers for reading process information.

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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cgroup_ids() {
        let flatpak = "0::/user.slice/user-1000.slice/user@1000.service/app.slice/app-flatpak-com.discordapp.Discord-1234.scope";
        assert_eq!(
            app_id_from_cgroup(flatpak).as_deref(),
            Some("com.discordapp.Discord")
        );
        let gnome = "0::/user.slice/user-1000.slice/user@1000.service/app.slice/app-gnome-google\\x2dchrome-5678.scope";
        assert_eq!(app_id_from_cgroup(gnome).as_deref(), Some("google-chrome"));
        let kde = "0::/user.slice/user-1000.slice/user@1000.service/app.slice/app-org.kde.dolphin@0a1b.service";
        assert_eq!(app_id_from_cgroup(kde).as_deref(), Some("org.kde.dolphin"));
        assert_eq!(app_id_from_cgroup("0::/system.slice/sshd.service"), None);
    }
}
