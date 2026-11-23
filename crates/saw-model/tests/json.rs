//! Tests for the JSON writer.

use saw_model::json::*;

#[test]
fn floats_read_as_python_writes_them() {
    for (value, python) in [
        (0.1, "0.1"), (1.0, "1.0"), (-2.5, "-2.5"), (100.0, "100.0"), (1e15, "1000000000000000.0"),
        (1e16, "1e+16"), (1.5e300, "1.5e+300"), (0.0001, "0.0001"), (0.00001, "1e-05"),
        (1.25e-7, "1.25e-07"), (123456.789, "123456.789"), (0.0, "0.0"), (-0.0, "-0.0"),
        (f64::INFINITY, "Infinity"), (f64::NAN, "NaN"),
    ] {
        assert_eq!(python_float(value), python, "{value:e}");
    }
}
