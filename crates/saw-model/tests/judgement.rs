//! Tests for judgements.

use saw_model::judgement::*;

#[test]
fn the_outcomes_rank_as_the_plan_orders_them() {
    let mut ranked = [Outcome::Suspicious, Outcome::Clean, Outcome::Infected, Outcome::Residue, Outcome::NotVerified];
    ranked.sort();
    assert_eq!(ranked, [Outcome::Clean, Outcome::Residue, Outcome::Suspicious, Outcome::NotVerified, Outcome::Infected]);
}

#[test]
fn coverage_is_complete_only_with_no_gap() {
    assert!(Coverage::default().is_complete());
    let cut = Coverage { gaps: vec![Gap { kind: GapKind::OutOfTime, detail: "the deadline".into() }] };
    assert!(!cut.is_complete());
}
