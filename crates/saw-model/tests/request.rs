//! Tests for requests.

use saw_model::request::*;

#[test]
fn raising_a_depth_never_lowers_it() {
    let all = [Depth::DEFAULT, Depth { deep: true, history: false }, Depth { deep: false, history: true },
               Depth { deep: true, history: true }];
    for a in all {
        for b in all {
            let raised = a.raised(b);
            assert!(raised.deep >= a.deep && raised.deep >= b.deep);
            assert!(raised.history >= a.history && raised.history >= b.history);
            assert_eq!(raised, b.raised(a));
        }
    }
}
