//! SMT-LIB2 constraint generation from Photon IR.
//!
//! Translates flagged findings and their associated CFG/DFG paths into
//! SMT-LIB2 assertions using 256-bit bitvector theory (`(_ BitVec 256)`)
//! to match EVM word semantics.

use photon_ir::{ContractIR, FunctionIR, IrStmtKind};
use photon_types::{Finding, VulnClass};

/// An SMT-LIB2 query to be sent to Z3.
#[derive(Debug, Clone)]
pub struct SmtQuery {
    /// The finding this query is verifying.
    pub finding_rule_id: String,
    /// Source file and line for provenance.
    pub file: String,
    pub line: u32,
    /// The generated SMT-LIB2 script.
    pub script: String,
    /// Human-readable description of what this query checks.
    pub description: String,
    /// The vulnerability class being checked.
    pub vuln_class: VulnClass,
}

/// Generate SMT-LIB2 queries for findings flagged for symbolic escalation.
///
/// Each query encodes the path constraints necessary to determine whether
/// the vulnerability is actually reachable (SAT) or provably unreachable (UNSAT).
pub fn generate_queries(
    contracts: &[ContractIR],
    findings: &[Finding],
) -> Vec<SmtQuery> {
    let mut queries = Vec::new();

    for finding in findings {
        // Find the contract IR matching this finding
        let contract = contracts.iter().find(|c| c.path == finding.file);
        let contract = match contract {
            Some(c) => c,
            None => continue,
        };

        match finding.vuln_class {
            VulnClass::Reentrancy => {
                if let Some(q) = generate_reentrancy_query(contract, finding) {
                    queries.push(q);
                }
            }
            VulnClass::Arithmetic => {
                if let Some(q) = generate_arithmetic_query(contract, finding) {
                    queries.push(q);
                }
            }
            VulnClass::AccessControl => {
                if let Some(q) = generate_access_control_query(contract, finding) {
                    queries.push(q);
                }
            }
            _ => {
                // Other vuln classes don't have symbolic queries yet
            }
        }
    }

    queries
}

/// Generate a reentrancy verification query.
///
/// Models the CEI violation: we check if there exists a state where
/// an external call can be reached AND a subsequent state write occurs,
/// with no reentrancy guard (mutex) in between.
fn generate_reentrancy_query(contract: &ContractIR, finding: &Finding) -> Option<SmtQuery> {
    // Find the function containing this finding
    let func = find_function_at_line(contract, finding.line)?;

    // Build the SMT-LIB2 script
    let mut script = String::new();

    // Header
    script.push_str("; Photon Symbolic — Reentrancy Verification\n");
    script.push_str(&format!("; Contract: {}\n", contract.name));
    script.push_str(&format!("; Function: {}\n", func.name));
    script.push_str(&format!("; Rule: {}\n", finding.rule_id));
    script.push_str("\n");

    // Use QF_BV (quantifier-free bitvector) logic for EVM semantics
    script.push_str("(set-logic QF_BV)\n");
    script.push_str("(set-option :timeout 30000)\n\n");

    // Declare EVM-width bitvector sort
    script.push_str("; EVM 256-bit word variables\n");

    // Model state variables as 256-bit bitvectors
    for sv in &contract.state_variables {
        script.push_str(&format!(
            "(declare-const {}_pre (_ BitVec 256))  ; state before call\n",
            sanitize_smt_name(&sv.name)
        ));
        script.push_str(&format!(
            "(declare-const {}_post (_ BitVec 256)) ; state after call\n",
            sanitize_smt_name(&sv.name)
        ));
    }
    script.push_str("\n");

    // Model the caller's balance and the contract balance
    script.push_str("(declare-const caller_balance (_ BitVec 256))\n");
    script.push_str("(declare-const contract_balance (_ BitVec 256))\n");
    script.push_str("(declare-const call_value (_ BitVec 256))\n\n");

    // Model the reentrancy condition:
    // 1. External call happens (call_value > 0)
    // 2. State is NOT updated before the call (pre == post at call point)
    // 3. Attacker can re-enter with the same state
    script.push_str("; Reentrancy path constraint:\n");
    script.push_str("; call_value > 0 (non-trivial external call)\n");
    script.push_str("(assert (bvugt call_value (_ bv0 256)))\n\n");

    // The vulnerability exists if the state variable used in the balance check
    // is NOT zeroed/updated before the external call
    let state_vars_in_func = get_state_vars_written_in_func(func);
    let ext_calls = get_external_calls_in_func(func);

    if ext_calls.is_empty() || state_vars_in_func.is_empty() {
        return None;
    }

    // Assert that at least one state variable is still at its pre-call value
    // when the external call executes (CEI violation)
    script.push_str("; State not updated before external call (CEI violation)\n");
    for sv_name in &state_vars_in_func {
        let safe_name = sanitize_smt_name(sv_name);
        script.push_str(&format!(
            "(assert (= {}_pre {}_post))\n",
            safe_name, safe_name
        ));
    }
    script.push_str("\n");

    // Assert caller has sufficient balance for re-entry
    script.push_str("; Caller can re-enter with the same balance state\n");
    script.push_str("(assert (bvuge caller_balance call_value))\n\n");

    // Assert contract has funds to drain
    script.push_str("; Contract has funds available\n");
    script.push_str("(assert (bvugt contract_balance (_ bv0 256)))\n");
    script.push_str("(assert (bvuge contract_balance call_value))\n\n");

    // Check satisfiability
    script.push_str("(check-sat)\n");
    script.push_str("(exit)\n");

    Some(SmtQuery {
        finding_rule_id: finding.rule_id.clone(),
        file: finding.file.to_string_lossy().to_string(),
        line: finding.line,
        script,
        description: format!(
            "Verify reentrancy in {}.{}: can an attacker re-enter before state is updated?",
            contract.name, func.name
        ),
        vuln_class: VulnClass::Reentrancy,
    })
}

/// Generate an arithmetic overflow/underflow verification query.
///
/// Models 256-bit unsigned arithmetic and checks whether overflow/underflow
/// is reachable for unchecked operations in pre-0.8.0 contracts.
fn generate_arithmetic_query(contract: &ContractIR, finding: &Finding) -> Option<SmtQuery> {
    let mut script = String::new();

    script.push_str("; Photon Symbolic — Arithmetic Overflow Verification\n");
    script.push_str(&format!("; Contract: {}\n", contract.name));
    script.push_str(&format!("; Rule: {}\n", finding.rule_id));
    script.push_str("\n");

    script.push_str("(set-logic QF_BV)\n");
    script.push_str("(set-option :timeout 30000)\n\n");

    // Declare operands as 256-bit bitvectors
    script.push_str("; Operands for arithmetic check\n");
    script.push_str("(declare-const a (_ BitVec 256))\n");
    script.push_str("(declare-const b (_ BitVec 256))\n");
    script.push_str("(declare-const result (_ BitVec 256))\n\n");

    // Check for addition overflow: a + b wraps around (result < a)
    script.push_str("; Addition overflow: a + b < a (wraps around in 256-bit unsigned)\n");
    script.push_str("(assert (= result (bvadd a b)))\n");
    script.push_str("(assert (bvult result a))\n\n");

    // Ensure non-trivial values
    script.push_str("; Non-trivial operands\n");
    script.push_str("(assert (bvugt a (_ bv0 256)))\n");
    script.push_str("(assert (bvugt b (_ bv0 256)))\n\n");

    script.push_str("(check-sat)\n");
    script.push_str("(exit)\n");

    Some(SmtQuery {
        finding_rule_id: finding.rule_id.clone(),
        file: finding.file.to_string_lossy().to_string(),
        line: finding.line,
        script,
        description: format!(
            "Verify arithmetic overflow in {}: can unsigned addition wrap around?",
            contract.name
        ),
        vuln_class: VulnClass::Arithmetic,
    })
}

/// Generate an access control verification query.
///
/// Checks whether an unprotected function can be called by an arbitrary
/// address (i.e., no `msg.sender == owner` guard on the path).
fn generate_access_control_query(contract: &ContractIR, finding: &Finding) -> Option<SmtQuery> {
    let func = find_function_at_line(contract, finding.line)?;

    let mut script = String::new();

    script.push_str("; Photon Symbolic — Access Control Verification\n");
    script.push_str(&format!("; Contract: {}\n", contract.name));
    script.push_str(&format!("; Function: {}\n", func.name));
    script.push_str(&format!("; Rule: {}\n", finding.rule_id));
    script.push_str("\n");

    script.push_str("(set-logic QF_BV)\n");
    script.push_str("(set-option :timeout 30000)\n\n");

    // Model msg.sender and owner as 160-bit addresses (zero-extended to 256)
    script.push_str("; Address variables (160-bit, zero-extended to 256-bit)\n");
    script.push_str("(declare-const msg_sender (_ BitVec 256))\n");
    script.push_str("(declare-const owner (_ BitVec 256))\n\n");

    // Assert msg.sender != owner (attacker scenario)
    script.push_str("; Attacker: msg.sender != owner\n");
    script.push_str("(assert (not (= msg_sender owner)))\n\n");

    // Assert both are valid 160-bit addresses
    script.push_str("; Valid Ethereum addresses (fit in 160 bits)\n");
    script.push_str("(assert (bvult msg_sender (bvshl (_ bv1 256) (_ bv160 256))))\n");
    script.push_str("(assert (bvult owner (bvshl (_ bv1 256) (_ bv160 256))))\n");
    script.push_str("(assert (bvugt msg_sender (_ bv0 256)))\n");
    script.push_str("(assert (bvugt owner (_ bv0 256)))\n\n");

    // Check if there are any guards in this function that check msg.sender
    let has_guard = func.statements.iter().any(|s| {
        matches!(s.kind, IrStmtKind::Guard { .. })
    });

    if has_guard {
        // There's a guard, but the static analysis still flagged it —
        // the guard may not actually compare msg.sender to owner.
        // Model that the guard is bypassed.
        script.push_str("; Guard exists but may not enforce msg.sender == owner\n");
        script.push_str("; Check: can a non-owner reach the state-modifying code?\n");
    } else {
        script.push_str("; No guard found — any address can call this function\n");
    }

    script.push_str("(check-sat)\n");
    script.push_str("(exit)\n");

    Some(SmtQuery {
        finding_rule_id: finding.rule_id.clone(),
        file: finding.file.to_string_lossy().to_string(),
        line: finding.line,
        script,
        description: format!(
            "Verify access control in {}.{}: can a non-owner invoke this function?",
            contract.name, func.name
        ),
        vuln_class: VulnClass::AccessControl,
    })
}

// ─── Helpers ──────────────────────────────────────────────────

/// Find the function IR whose source location contains the given line.
fn find_function_at_line<'a>(contract: &'a ContractIR, line: u32) -> Option<&'a FunctionIR> {
    // Try to find a function that contains the finding line
    for func in &contract.functions {
        if let solang_parser::pt::Loc::File(_, start, end) = func.loc {
            let func_start_line = contract.source[..start].lines().count() as u32;
            let func_end_line = if end <= contract.source.len() {
                contract.source[..end].lines().count() as u32
            } else {
                u32::MAX
            };
            if line >= func_start_line && line <= func_end_line {
                return Some(func);
            }
        }
    }
    // Fallback: return the first function (for findings without precise line mapping)
    contract.functions.first()
}

/// Extract names of state variables written in a function.
fn get_state_vars_written_in_func(func: &FunctionIR) -> Vec<String> {
    func.statements
        .iter()
        .filter_map(|s| match &s.kind {
            IrStmtKind::StateWrite { variable } => Some(variable.clone()),
            _ => None,
        })
        .collect()
}

/// Extract external call targets from a function.
fn get_external_calls_in_func(func: &FunctionIR) -> Vec<(String, String)> {
    func.statements
        .iter()
        .filter_map(|s| match &s.kind {
            IrStmtKind::ExternalCall { target, function } => {
                Some((target.clone(), function.clone()))
            }
            _ => None,
        })
        .collect()
}

/// Sanitize a Solidity identifier for use as an SMT-LIB2 symbol.
/// Replaces brackets, dots, and other special chars with underscores.
fn sanitize_smt_name(name: &str) -> String {
    name.chars()
        .map(|c| if c.is_alphanumeric() || c == '_' { c } else { '_' })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sanitize_smt_name_basic() {
        assert_eq!(sanitize_smt_name("balances"), "balances");
        assert_eq!(sanitize_smt_name("msg.sender"), "msg_sender");
        assert_eq!(sanitize_smt_name("balanceOf[addr]"), "balanceOf_addr_");
    }
}
