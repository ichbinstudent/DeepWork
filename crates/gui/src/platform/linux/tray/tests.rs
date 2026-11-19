use super::*;
use crate::platform::tray_menu::test_util::*;

#[test]
fn menu_layout_ids() {
    let (_, items) = compute(Some(&status(vec![block(true, false)])), 0.0, Some(true));
    let m = Menu::build(items);
    let (id, _, children) = m.layout(0, -1);
    assert_eq!(id, 0);
    assert!(!children.is_empty());
    let v = (1u32, m.layout(0, -1)).to_variant();
    assert_eq!(v.type_().as_str(), "(u(ia{sv}av))");
    // every id resolves
    for (id, _, kids) in &m.items {
        assert!(m.get(*id).is_some());
        for k in kids {
            assert!(m.get(*k).is_some());
        }
    }
}
