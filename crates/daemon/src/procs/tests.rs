use super::*;

#[test]
fn rule_matching() {
    let p = Proc {
        pid: 42,
        comm: "Discord".into(),
        exe: "/opt/discord/Discord".into(),
        argv0: "/opt/discord/Discord".into(),
        app_id: Some("com.discordapp.Discord".into()),
        ..Default::default()
    };
    assert!(matches("discord", &p));
    assert!(matches("com.discordapp.discord", &p));
    assert!(matches("/opt/discord/Discord", &p));
    assert!(!matches("disc", &p));
    let java = Proc {
        comm: "java".into(),
        cmdline: "/usr/bin/java -Xmx4G -cp a.jar net.minecraft.client.main.Main --username x"
            .into(),
        ..Default::default()
    };
    assert!(matches("cmd:net.minecraft.client.main.Main", &java));
    assert!(matches("cmd:NET.MINECRAFT.client", &java));
    assert!(!matches("cmd:net.fabricmc.loader", &java));
    assert!(!matches("java.minecraft", &java));
    let long = Proc {
        comm: "steamwebhelper_".into(),
        ..Default::default()
    };
    assert!(matches("steamwebhelper_long", &long));
    let win = Proc {
        comm: "Discord.exe".into(),
        exe: r"C:\Users\a\AppData\Local\Discord\app-1.0\Discord.exe".into(),
        ..Default::default()
    };
    assert!(matches("discord", &win));
    assert!(matches(
        r"C:\Users\a\AppData\Local\Discord\app-1.0\Discord.exe",
        &win
    ));
    assert!(matches(
        r"c:\users\A\appdata\local\discord\app-1.0\discord.exe",
        &win
    ));
    assert!(!matches("discord.ex", &win));
}

/// A fake process table that records what was closed.
struct Fake(
    Vec<Proc>,
    std::sync::Arc<std::sync::Mutex<Vec<(u32, bool)>>>,
);
impl ProcessTable for Fake {
    fn list(&self) -> Vec<Proc> {
        self.0.clone()
    }
    fn terminate(&self, processes: &[Proc], force: bool) {
        let mut log = self.1.lock().unwrap();
        log.extend(processes.iter().map(|p| (p.pid, force)));
    }
}

#[test]
fn killer_spares_privileged_and_protected() {
    let p = |pid, comm: &str, privileged| Proc {
        pid,
        comm: comm.into(),
        exe: format!("/usr/bin/{comm}"),
        system_exe: true,
        privileged,
        start_time: 1,
        ..Default::default()
    };
    let log = std::sync::Arc::new(std::sync::Mutex::new(vec![]));
    let table = Fake(
        vec![
            p(10, "steam", false),
            p(11, "steam", true),
            p(12, "deepwork", false),
        ],
        log.clone(),
    );
    let mut k = Killer::new(Box::new(table));
    let rules = [
        ("steam".to_string(), "Games".to_string()),
        ("deepwork".to_string(), "X".to_string()),
    ];
    let reported = k.enforce(&rules);
    assert_eq!(reported, vec![("steam".to_string(), "Games".to_string())]);
    assert_eq!(*log.lock().unwrap(), vec![(10, false)]);
}

/// A blocked program can't hide behind a protected name: the name it
/// gives itself doesn't count, and neither does a protected file name
/// on a copy a user made.
#[test]
fn protected_names_cant_be_borrowed() {
    const SHELL: &str = if cfg!(windows) { "cmd" } else { "bash" };
    let p = |pid, comm: &str, exe: &str, system_exe| Proc {
        pid,
        comm: comm.into(),
        exe: exe.into(),
        system_exe,
        cmdline: format!("{exe} net.minecraft.client.main.Main"),
        start_time: 1,
        ..Default::default()
    };
    let log = std::sync::Arc::new(std::sync::Mutex::new(vec![]));
    let table = Fake(
        vec![
            // renamed itself with prctl(PR_SET_NAME)
            p(20, SHELL, "/usr/lib/jvm/bin/java", true),
            // a copy of the game named like a shell
            p(21, SHELL, &format!("/home/a/.local/bin/{SHELL}"), false),
            // a real shell whose command line happens to match
            p(22, SHELL, &format!("/usr/bin/{SHELL}"), true),
        ],
        log.clone(),
    );
    let mut k = Killer::new(Box::new(table));
    let rules = [(
        "cmd:net.minecraft.client.main.Main".to_string(),
        "Games".to_string(),
    )];
    k.enforce(&rules);
    assert_eq!(*log.lock().unwrap(), vec![(20, false), (21, false)]);
}
