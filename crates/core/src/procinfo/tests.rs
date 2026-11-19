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
