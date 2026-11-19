use super::test_util::*;
use super::*;

#[test]
fn idle_and_offline() {
    let (look, items) = compute(None, 0.0, Some(true));
    assert_eq!(look.icon, "offline");
    assert!(items.iter().any(|i| i.action == Some(Action::Quit)));
    let (look, items) = compute(Some(&status(vec![block(false, false)])), 0.0, Some(true));
    assert_eq!(look.icon, "idle");
    assert_eq!(look.label, "");
    assert!(items.iter().any(|i| i.label == "Start a block"));
}

#[test]
fn locked_block_shows_timer_and_unlock() {
    let (look, items) = compute(Some(&status(vec![block(true, true)])), 0.0, Some(true));
    assert_eq!(look.icon, "locked");
    assert_eq!(look.label, "1h 05m");
    let sub = items.iter().find(|i| i.label.contains("Social")).unwrap();
    assert!(
        sub.children
            .iter()
            .any(|c| c.action == Some(Action::Unlock("b1".into())))
    );
    assert!(
        !sub.children
            .iter()
            .any(|c| c.action == Some(Action::Stop("b1".into())))
    );
    // A flat theme icon marks the lock, no (colored) emoji anywhere.
    assert_eq!(sub.icon, Some(LOCK_ICON));
    fn all(items: &[Item]) -> Vec<&Item> {
        items
            .iter()
            .flat_map(|i| std::iter::once(i).chain(all(&i.children)))
            .collect()
    }
    assert!(all(&items).iter().all(|i| {
        i.label.is_ascii()
            || i.label
                .chars()
                .all(|c| (c as u32) < 0x2000 || "—…".contains(c))
    }));
    let (look, _) = compute(Some(&status(vec![block(true, true)])), 0.0, Some(false));
    assert_eq!(look.label, "");
    // Without a timer toggle the countdown is still there (for the tooltip).
    let (look, items) = compute(Some(&status(vec![block(true, true)])), 0.0, None);
    assert_eq!(look.label, "1h 05m");
    assert!(items.iter().all(|i| i.action != Some(Action::ToggleTimer)));
}
