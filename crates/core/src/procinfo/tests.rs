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

#[test]
fn start_menu_entries() {
    let rules = |target: &str, arguments: &str, id: &str| {
        start_menu_rules(target, arguments, id).map(|r| r.join(","))
    };
    let some = |s: &str| Some(s.to_string());
    assert_eq!(
        rules(r"C:\Program Files\Steam\steam.exe", "", "Valve.Steam"),
        some("steam")
    );
    assert_eq!(
        rules(
            r"C:\Users\a\AppData\Local\Discord\Update.exe",
            "--processStart Discord.exe",
            "com.squirrel.Discord.Discord"
        ),
        some("Discord")
    );
    assert_eq!(
        rules("", "", "SpotifyAB.SpotifyMusic_zpdnekdrzrea0!Spotify"),
        some("SpotifyAB.SpotifyMusic_zpdnekdrzrea0")
    );
    assert_eq!(
        rules(r"D:\Games\X\Launcher.EXE", "", "x"),
        some(r"D:\Games\X\Launcher.EXE")
    );
    for none in [
        r"C:\App\unins000.exe",
        r"C:\App\Uninstall App.exe",
        r"C:\App\Update.exe",
        r"C:\App\readme.txt",
        r"C:\Chrome\chrome_proxy.exe",
        r"C:\Python\pythonw.exe",
        r"C:\DeepWork\deepwork.exe",
        "https://example.com/",
    ] {
        assert_eq!(rules(none, "", ""), None, "{none}");
    }
    assert_eq!(rules("", "", "Microsoft.Windows.Explorer"), None);
    assert_eq!(rules("", "", r"{GUID}\a_b.exe"), None);
}
