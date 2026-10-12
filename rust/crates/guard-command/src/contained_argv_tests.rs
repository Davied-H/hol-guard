use super::*;

#[test]
fn current_main_unittest_vectors() {
    let vectors: Value = serde_json::from_str(include_str!("../tests/fixtures/contained_unittest_parity.json")).unwrap();
    assert_eq!(vectors["cases"].as_array().unwrap().len(), 13);
    for case in vectors["cases"].as_array().unwrap() {
        assert_eq!(evaluate(case["operation"].as_str().unwrap(), &case["input"]).unwrap(), case["expected"]);
    }
}

#[test]
fn incoming_main_node_and_tsx_script_vectors() {
    let vectors: Value = serde_json::from_str(include_str!(
        "../tests/fixtures/contained_script_parity.json"
    ))
    .unwrap();
    assert_eq!(vectors["cases"].as_array().unwrap().len(), 44);
    for case in vectors["cases"].as_array().unwrap() {
        assert_eq!(
            evaluate(case["operation"].as_str().unwrap(), &case["input"]).unwrap(),
            case["expected"],
            "{case}"
        );
    }
}

#[test]
fn original_portable_contained_argv_vectors() {
    let vectors: Value = serde_json::from_str(include_str!(
        "../tests/fixtures/contained_execution_parity.json"
    ))
    .unwrap();
    let mut count = 0;
    for case in vectors["cases"].as_array().unwrap() {
        if let Some(result) = evaluate(case["operation"].as_str().unwrap(), &case["input"]) {
            assert_eq!(result, case["expected"], "case={case}");
            count += 1;
        }
    }
    assert!(count >= 80);
}
