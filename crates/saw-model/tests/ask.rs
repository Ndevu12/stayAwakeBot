//! Tests for questions asked of the user.

use saw_model::events::ask::*;

#[test]
fn an_answer_with_fields_saw_does_not_read_is_still_read() {
    let answer: Answer =
        serde_json::from_str(r#"{"id": "q1", "action": "take-out", "chosen": ["a.js"], "note": "mine"}"#).unwrap();
    assert_eq!((answer.action.as_str(), answer.chosen), ("take-out", Some(vec!["a.js".to_string()])));
}
