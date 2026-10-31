use super::support::*;

#[test]
fn jcs_sorts_utf16_keys_recursively_and_rejects_noninteger_numbers() {
    let input = json!({"\u{e000}": 1, "\u{1f600}": [{"z": 0, "a": 1}]});
    assert_eq!(
        String::from_utf8(canonical_bytes(&input).unwrap()).unwrap(),
        "{\"😀\":[{\"a\":1,\"z\":0}],\"\u{e000}\":1}"
    );
    assert!(canonical_bytes(&json!(1.5)).is_err());
    assert!(canonical_bytes(&json!(9_007_199_254_740_992u64)).is_err());
}
