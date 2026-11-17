//! The `saw` command.

use saw_model::release::RELEASE;

fn main() {
    if std::env::args().nth(1).as_deref() == Some("--version") {
        println!("saw (stayawakebot) {RELEASE}");
    }
}
