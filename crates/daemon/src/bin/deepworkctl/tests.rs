use super::*;

#[test]
fn add_arguments() {
    let cfg = parse_add(
        "Social",
        &[
            "--lock",
            "strict",
            "list:social",
            "https://www.Reddit.com/r/x",
        ],
    )
    .unwrap();
    assert_eq!(cfg.lock, LockKind::Strict);
    assert_eq!(cfg.lists, ["social"]);
    assert_eq!(cfg.websites, ["reddit.com"]);
    assert!(parse_add("x", &[]).is_err());
    assert!(parse_add("x", &["list:nope"]).is_err());
    assert_eq!(parse_add("x", &["@chat"]).unwrap().lists, ["chat"]);
    assert!(parse_add("x", &["--lock", "hardcore", "a.com"]).is_err());
}
