use super::*;

#[test]
fn roundtrip() {
    let ranges = vec![[540, 1020], [1440 + 540, 1440 + 1020], [10_050, 10_080]];
    assert_eq!(ranges_from_slots(&slots_from_ranges(&ranges)), ranges);
}
