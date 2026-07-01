//! Static analysis rules for Photon.
//!
//! Each rule implements the `Rule` trait and performs structural pattern matching
//! over the contract's IR (CFG/DFG) to detect specific vulnerability classes.

pub mod reentrancy;
pub mod access_control;
pub mod arithmetic;
pub mod oracle;

use crate::Rule;

/// Returns all built-in rules.
pub fn all_rules() -> Vec<Box<dyn Rule>> {
    vec![
        // Reentrancy rules
        Box::new(reentrancy::ReentrancyCeiViolation),
        Box::new(reentrancy::CrossFunctionReentrancy),
        // Access control rules
        Box::new(access_control::MissingAccessControl),
        Box::new(access_control::UnprotectedSelfDestruct),
        // Arithmetic rules
        Box::new(arithmetic::UncheckedArithmetic),
        // Oracle rules
        Box::new(oracle::SingleSourceOracle),
    ]
}
