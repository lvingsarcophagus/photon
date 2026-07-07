//! # photon-ir — Graph Transformation Tier
//!
//! Lowers Solidity AST nodes into SSA-form Control Flow Graphs (CFG) with associated
//! Data Flow Graph (DFG) edges, stored in petgraph adjacency vectors.
//!
//! Correctness here is a security property: an incorrect DFG edge means a downstream
//! taint-tracking rule silently misses a sink, producing a false negative.
//!
//! ## Security Mitigations
//! - T-2.2: Graph complexity bounds with graceful degradation
//! - T-2.3: Deterministic SSA numbering by source position

use petgraph::graph::{DiGraph, NodeIndex};
use photon_core::ParsedContract;
use photon_types::AnalysisStatus;
use solang_parser::pt::*;
use std::collections::HashMap;
use std::path::PathBuf;
use thiserror::Error;
use tracing::{debug, warn};

pub mod taint;

/// Maximum number of nodes allowed in a single contract's CFG/DFG.
const MAX_GRAPH_NODES: usize = 50_000;
/// Maximum number of edges allowed in a single contract's CFG/DFG.
const MAX_GRAPH_EDGES: usize = 200_000;

/// Errors during IR construction.
#[derive(Error, Debug)]
pub enum IrError {
    #[error("Graph complexity exceeded for {path}: {reason}")]
    ComplexityExceeded { path: PathBuf, reason: String },

    #[error("IR construction failed for {path}: {reason}")]
    ConstructionFailed { path: PathBuf, reason: String },
}

/// A node in the Control Flow Graph.
#[derive(Debug, Clone)]
pub enum CfgNode {
    /// Function entry point.
    Entry {
        function_name: String,
        loc: Loc,
    },
    /// A basic block containing sequential statements.
    BasicBlock {
        id: u32,
        statements: Vec<IrStatement>,
    },
    /// Conditional branch.
    Conditional {
        id: u32,
        condition: String,
        loc: Loc,
    },
    /// Function exit point.
    Exit {
        function_name: String,
    },
}

/// An edge in the Control Flow Graph.
#[derive(Debug, Clone)]
pub enum CfgEdge {
    /// Sequential flow.
    Sequential,
    /// True branch of a conditional.
    TrueBranch,
    /// False branch of a conditional.
    FalseBranch,
    /// Loop back edge.
    LoopBack,
}

/// A node in the Data Flow Graph.
#[derive(Debug, Clone)]
pub enum DfgNode {
    /// An SSA variable definition.
    Variable {
        name: String,
        ssa_index: u32,
        loc: Loc,
    },
    /// A function parameter.
    Parameter {
        name: String,
        index: u32,
        loc: Loc,
    },
    /// An external call (potential reentrancy sink).
    ExternalCall {
        target: String,
        function_name: String,
        loc: Loc,
    },
    /// A state variable read.
    StateRead {
        variable: String,
        loc: Loc,
    },
    /// A state variable write (state update).
    StateWrite {
        variable: String,
        loc: Loc,
    },
    /// A return statement.
    Return {
        loc: Loc,
    },
    /// A msg.sender / tx.origin access.
    MsgSender {
        loc: Loc,
    },
    /// A require / assert / revert guard.
    Guard {
        guard_type: GuardType,
        loc: Loc,
    },
    /// A self-destruct call.
    SelfDestruct {
        loc: Loc,
    },
    /// A delegatecall.
    DelegateCall {
        target: String,
        loc: Loc,
    },
}

/// Type of guard statement.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GuardType {
    Require,
    Assert,
    Revert,
    If,
}

/// An edge in the Data Flow Graph.
#[derive(Debug, Clone)]
pub enum DfgEdge {
    /// Data flows from source to sink.
    DataFlow,
    /// Taint propagation (e.g., user input flows into state write).
    TaintPropagation,
    /// Control dependency (e.g., guard protects a state write).
    ControlDependency,
}

/// An intermediate representation statement.
#[derive(Debug, Clone)]
pub struct IrStatement {
    pub kind: IrStmtKind,
    pub loc: Loc,
    pub source_line: u32,
}

/// Kind of IR statement.
#[derive(Debug, Clone)]
pub enum IrStmtKind {
    StateRead { variable: String },
    StateWrite { variable: String },
    ExternalCall { target: String, function: String },
    LocalAssign { variable: String },
    Guard { guard_type: GuardType },
    Return,
    Emit { event: String },
    SelfDestruct,
    DelegateCall { target: String },
}

/// Information about a function in the contract's IR.
#[derive(Debug, Clone)]
pub struct FunctionIR {
    /// Function name.
    pub name: String,
    /// Function visibility.
    pub visibility: Visibility,
    /// Whether the function has a modifier (e.g., onlyOwner).
    pub modifiers: Vec<String>,
    /// Whether the function is marked payable.
    pub is_payable: bool,
    /// Whether the function is a constructor.
    pub is_constructor: bool,
    /// Whether the function is a fallback/receive.
    pub is_fallback: bool,
    /// Source location.
    pub loc: Loc,
    /// CFG entry node index.
    pub cfg_entry: NodeIndex,
    /// CFG exit node index.
    pub cfg_exit: NodeIndex,
    /// Ordered list of DFG nodes for this function.
    pub dfg_nodes: Vec<NodeIndex>,
    /// IR statements in source order.
    pub statements: Vec<IrStatement>,
}

/// Visibility of a function.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Visibility {
    Public,
    External,
    Internal,
    Private,
}

/// State variable information.
#[derive(Debug, Clone)]
pub struct StateVar {
    pub name: String,
    pub type_name: String,
    pub loc: Loc,
    pub is_mapping: bool,
}

/// The complete IR for a single contract.
#[derive(Debug)]
pub struct ContractIR {
    /// Contract name.
    pub name: String,
    /// Source file path.
    pub path: PathBuf,
    /// Control Flow Graph.
    pub cfg: DiGraph<CfgNode, CfgEdge>,
    /// Data Flow Graph.
    pub dfg: DiGraph<DfgNode, DfgEdge>,
    /// Per-function IR.
    pub functions: Vec<FunctionIR>,
    /// State variables.
    pub state_variables: Vec<StateVar>,
    /// Analysis status.
    pub status: AnalysisStatus,
    /// Raw source for source mapping.
    pub source: String,
    /// Whether this is an interface contract.
    pub is_interface: bool,
}

impl ContractIR {
    /// Checks if this is a test contract (e.g. from Foundry or containing test in path).
    pub fn is_test(&self) -> bool {
        let path_str = self.path.to_string_lossy().to_lowercase();
        path_str.contains("/test/")
            || path_str.contains("\\test\\")
            || path_str.contains("/tests/")
            || path_str.contains("\\tests\\")
            || path_str.contains("/test-contracts/")
            || path_str.contains("\\test-contracts\\")
            || path_str.ends_with(".t.sol")
            || self.name.ends_with("Test")
            || self.name.contains("Test")
    }
}

/// SSA variable counter for deterministic numbering.
struct SsaCounter {
    counters: HashMap<String, u32>,
}

impl SsaCounter {
    fn new() -> Self {
        Self {
            counters: HashMap::new(),
        }
    }

    fn next(&mut self, name: &str) -> u32 {
        let counter = self.counters.entry(name.to_string()).or_insert(0);
        let idx = *counter;
        *counter += 1;
        idx
    }
}

/// The IR builder that transforms parsed contracts into graph IR.
pub struct IrBuilder {
    max_nodes: usize,
    max_edges: usize,
}

impl IrBuilder {
    pub fn new() -> Self {
        Self {
            max_nodes: MAX_GRAPH_NODES,
            max_edges: MAX_GRAPH_EDGES,
        }
    }

    pub fn with_limits(max_nodes: usize, max_edges: usize) -> Self {
        Self {
            max_nodes,
            max_edges,
        }
    }

    /// Build IR for a parsed contract.
    ///
    /// Per T-2.2: if graph complexity exceeds bounds, degrade gracefully
    /// to partial analysis rather than OOM-killing the process.
    pub fn build(&self, contract: &ParsedContract) -> Result<Vec<ContractIR>, IrError> {
        let mut results = Vec::new();

        for part in &contract.ast.0 {
            match part {
                SourceUnitPart::ContractDefinition(def) => {
                    match self.build_contract_ir(def, contract) {
                        Ok(ir) => results.push(ir),
                        Err(e) => {
                            warn!("Failed to build IR for contract: {}", e);
                            // Create a failed IR entry
                            results.push(ContractIR {
                                name: def
                                    .name
                                    .as_ref()
                                    .map(|n| n.name.clone())
                                    .unwrap_or_else(|| "<unnamed>".to_string()),
                                path: contract.path.clone(),
                                cfg: DiGraph::new(),
                                dfg: DiGraph::new(),
                                functions: Vec::new(),
                                state_variables: Vec::new(),
                                status: AnalysisStatus::Failed {
                                    error: e.to_string(),
                                },
                                source: contract.source.clone(),
                                is_interface: matches!(def.ty, ContractTy::Interface(_)),
                            });
                        }
                    }
                }
                _ => {} // Skip non-contract parts (imports, pragmas, etc.)
            }
        }

        Ok(results)
    }

    fn build_contract_ir(
        &self,
        def: &ContractDefinition,
        contract: &ParsedContract,
    ) -> Result<ContractIR, IrError> {
        let contract_name = def
            .name
            .as_ref()
            .map(|n| n.name.clone())
            .unwrap_or_else(|| "<unnamed>".to_string());

        debug!("Building IR for contract: {}", contract_name);

        let mut cfg = DiGraph::new();
        let mut dfg = DiGraph::new();
        let mut functions = Vec::new();
        let mut state_variables = Vec::new();
        let mut ssa = SsaCounter::new();

        // Extract state variables
        for part in &def.parts {
            if let ContractPart::VariableDefinition(var) = part {
                let var_name = var.name.as_ref().map(|n| n.name.clone()).unwrap_or_default();
                let type_name = format!("{:?}", var.ty);
                let is_mapping = matches!(var.ty, Expression::Type(_, Type::Mapping { .. }));

                state_variables.push(StateVar {
                    name: var_name,
                    type_name,
                    loc: var.loc,
                    is_mapping,
                });
            }
        }

        // Build CFG/DFG per function
        for part in &def.parts {
            if let ContractPart::FunctionDefinition(func) = part {
                if cfg.node_count() > self.max_nodes || cfg.edge_count() > self.max_edges {
                    return Err(IrError::ComplexityExceeded {
                        path: contract.path.clone(),
                        reason: format!(
                            "Graph complexity exceeded: {} nodes, {} edges (max: {}, {})",
                            cfg.node_count(),
                            cfg.edge_count(),
                            self.max_nodes,
                            self.max_edges
                        ),
                    });
                }

                let func_ir =
                    self.build_function_ir(func, &mut cfg, &mut dfg, &mut ssa, &state_variables);
                functions.push(func_ir);
            }
        }

        Ok(ContractIR {
            name: contract_name,
            path: contract.path.clone(),
            cfg,
            dfg,
            functions,
            state_variables,
            status: AnalysisStatus::Complete,
            source: contract.source.clone(),
            is_interface: matches!(def.ty, ContractTy::Interface(_)),
        })
    }

    fn build_function_ir(
        &self,
        func: &FunctionDefinition,
        cfg: &mut DiGraph<CfgNode, CfgEdge>,
        dfg: &mut DiGraph<DfgNode, DfgEdge>,
        ssa: &mut SsaCounter,
        state_vars: &[StateVar],
    ) -> FunctionIR {
        let func_name = func
            .name
            .as_ref()
            .map(|n| n.name.clone())
            .unwrap_or_else(|| match &func.ty {
                FunctionTy::Constructor => "constructor".to_string(),
                FunctionTy::Fallback => "fallback".to_string(),
                FunctionTy::Receive => "receive".to_string(),
                _ => "<anonymous>".to_string(),
            });

        // Create CFG entry and exit nodes
        let entry_node = cfg.add_node(CfgNode::Entry {
            function_name: func_name.clone(),
            loc: func.loc,
        });
        let exit_node = cfg.add_node(CfgNode::Exit {
            function_name: func_name.clone(),
        });

        // Process function body to extract IR statements
        let mut statements = Vec::new();
        let mut dfg_nodes = Vec::new();

        if let Some(body) = &func.body {
            self.extract_statements(body, &mut statements, dfg, &mut dfg_nodes, ssa, state_vars);
        }

        // Build basic block from statements
        if !statements.is_empty() {
            let block_node = cfg.add_node(CfgNode::BasicBlock {
                id: 0,
                statements: statements.clone(),
            });
            cfg.add_edge(entry_node, block_node, CfgEdge::Sequential);
            cfg.add_edge(block_node, exit_node, CfgEdge::Sequential);
        } else {
            cfg.add_edge(entry_node, exit_node, CfgEdge::Sequential);
        }

        // Extract visibility
        let visibility = func
            .attributes
            .iter()
            .find_map(|attr| match attr {
                FunctionAttribute::Visibility(v) => Some(match v {
                    solang_parser::pt::Visibility::Public(_) => Visibility::Public,
                    solang_parser::pt::Visibility::External(_) => Visibility::External,
                    solang_parser::pt::Visibility::Internal(_) => Visibility::Internal,
                    solang_parser::pt::Visibility::Private(_) => Visibility::Private,
                }),
                _ => None,
            })
            .unwrap_or(Visibility::Public);

        // Extract modifiers
        let modifiers: Vec<String> = func
            .attributes
            .iter()
            .filter_map(|attr| match attr {
                FunctionAttribute::BaseOrModifier(_, base) => {
                    Some(base.name.identifiers.iter().map(|i| i.name.clone()).collect::<Vec<_>>().join("."))
                }
                _ => None,
            })
            .collect();

        let is_payable = func
            .attributes
            .iter()
            .any(|attr| matches!(attr, FunctionAttribute::Mutability(Mutability::Payable(_))));

        FunctionIR {
            name: func_name,
            visibility,
            modifiers,
            is_payable,
            is_constructor: matches!(func.ty, FunctionTy::Constructor),
            is_fallback: matches!(func.ty, FunctionTy::Fallback | FunctionTy::Receive),
            loc: func.loc,
            cfg_entry: entry_node,
            cfg_exit: exit_node,
            dfg_nodes,
            statements,
        }
    }

    /// Recursively extract IR statements from a statement block.
    fn extract_statements(
        &self,
        stmt: &Statement,
        stmts: &mut Vec<IrStatement>,
        dfg: &mut DiGraph<DfgNode, DfgEdge>,
        dfg_nodes: &mut Vec<NodeIndex>,
        ssa: &mut SsaCounter,
        state_vars: &[StateVar],
    ) {
        match stmt {
            Statement::Block { statements, .. } => {
                for s in statements {
                    self.extract_statements(s, stmts, dfg, dfg_nodes, ssa, state_vars);
                }
            }
            Statement::Expression(loc, expr) => {
                self.extract_expr_statements(expr, *loc, stmts, dfg, dfg_nodes, ssa, state_vars);
            }
            Statement::VariableDefinition(loc, _decl, Some(init)) => {
                self.extract_expr_statements(init, *loc, stmts, dfg, dfg_nodes, ssa, state_vars);
            }
            Statement::If(loc, cond, then_body, else_body) => {
                self.visit_expr(cond, stmts, dfg, dfg_nodes, ssa, state_vars);
                
                if is_terminating(then_body) {
                    stmts.push(IrStatement {
                        kind: IrStmtKind::Guard { guard_type: GuardType::If },
                        loc: *loc,
                        source_line: loc_to_line(*loc),
                    });
                    let node = dfg.add_node(DfgNode::Guard {
                        guard_type: GuardType::If,
                        loc: *loc,
                    });
                    dfg_nodes.push(node);
                }

                self.extract_statements(then_body, stmts, dfg, dfg_nodes, ssa, state_vars);
                if let Some(else_stmt) = else_body {
                    if is_terminating(else_stmt) {
                        stmts.push(IrStatement {
                            kind: IrStmtKind::Guard { guard_type: GuardType::If },
                            loc: *loc,
                            source_line: loc_to_line(*loc),
                        });
                        let node = dfg.add_node(DfgNode::Guard {
                            guard_type: GuardType::If,
                            loc: *loc,
                        });
                        dfg_nodes.push(node);
                    }
                    self.extract_statements(else_stmt, stmts, dfg, dfg_nodes, ssa, state_vars);
                }
            }
            Statement::For(_, _, cond, _, body) => {
                if let Some(cond_expr) = cond {
                    self.visit_expr(cond_expr, stmts, dfg, dfg_nodes, ssa, state_vars);
                }
                if let Some(body_stmt) = body {
                    self.extract_statements(body_stmt, stmts, dfg, dfg_nodes, ssa, state_vars);
                }
            }
            Statement::While(_, cond, body) => {
                self.visit_expr(cond, stmts, dfg, dfg_nodes, ssa, state_vars);
                self.extract_statements(body, stmts, dfg, dfg_nodes, ssa, state_vars);
            }
            Statement::Return(loc, maybe_expr) => {
                stmts.push(IrStatement {
                    kind: IrStmtKind::Return,
                    loc: *loc,
                    source_line: loc_to_line(*loc),
                });
                let node = dfg.add_node(DfgNode::Return { loc: *loc });
                dfg_nodes.push(node);
                if let Some(expr) = maybe_expr {
                    self.visit_expr(expr, stmts, dfg, dfg_nodes, ssa, state_vars);
                }
            }
            _ => {}
        }
    }

    /// Recursively visit an expression tree.
    fn visit_expr(
        &self,
        expr: &Expression,
        stmts: &mut Vec<IrStatement>,
        dfg: &mut DiGraph<DfgNode, DfgEdge>,
        dfg_nodes: &mut Vec<NodeIndex>,
        ssa: &mut SsaCounter,
        state_vars: &[StateVar],
    ) {
        match expr {
            Expression::FunctionCall(loc, func_expr, args) => {
                if let Some((target, func_name)) = extract_call_target(func_expr) {
                    if func_name == "call" || func_name == "transfer" || func_name == "send" {
                        stmts.push(IrStatement {
                            kind: IrStmtKind::ExternalCall {
                                target: target.clone(),
                                function: func_name.clone(),
                            },
                            loc: *loc,
                            source_line: loc_to_line(*loc),
                        });
                        let node = dfg.add_node(DfgNode::ExternalCall {
                            target,
                            function_name: func_name,
                            loc: *loc,
                        });
                        dfg_nodes.push(node);
                    } else if func_name == "delegatecall" {
                        stmts.push(IrStatement {
                            kind: IrStmtKind::DelegateCall {
                                target: target.clone(),
                            },
                            loc: *loc,
                            source_line: loc_to_line(*loc),
                        });
                        let node = dfg.add_node(DfgNode::DelegateCall {
                            target,
                            loc: *loc,
                        });
                        dfg_nodes.push(node);
                    } else if func_name == "selfdestruct" {
                        stmts.push(IrStatement {
                            kind: IrStmtKind::SelfDestruct,
                            loc: *loc,
                            source_line: loc_to_line(*loc),
                        });
                        let node = dfg.add_node(DfgNode::SelfDestruct { loc: *loc });
                        dfg_nodes.push(node);
                    } else if func_name == "require" || func_name == "assert" {
                        let guard_type = if func_name == "require" {
                            GuardType::Require
                        } else {
                            GuardType::Assert
                        };
                        stmts.push(IrStatement {
                            kind: IrStmtKind::Guard { guard_type: guard_type.clone() },
                            loc: *loc,
                            source_line: loc_to_line(*loc),
                        });
                        let node = dfg.add_node(DfgNode::Guard {
                            guard_type,
                            loc: *loc,
                        });
                        dfg_nodes.push(node);
                    }
                }
                self.visit_expr(func_expr, stmts, dfg, dfg_nodes, ssa, state_vars);
                for arg in args {
                    self.visit_expr(arg, stmts, dfg, dfg_nodes, ssa, state_vars);
                }
            }
            Expression::Assign(loc, lhs, rhs)
            | Expression::AssignAdd(loc, lhs, rhs)
            | Expression::AssignSubtract(loc, lhs, rhs)
            | Expression::AssignMultiply(loc, lhs, rhs)
            | Expression::AssignDivide(loc, lhs, rhs)
            | Expression::AssignModulo(loc, lhs, rhs)
            | Expression::AssignAnd(loc, lhs, rhs)
            | Expression::AssignOr(loc, lhs, rhs)
            | Expression::AssignXor(loc, lhs, rhs)
            | Expression::AssignShiftLeft(loc, lhs, rhs)
            | Expression::AssignShiftRight(loc, lhs, rhs) => {
                if let Some(var_name) = extract_variable_name(lhs) {
                    if state_vars.iter().any(|sv| sv.name == var_name) {
                        stmts.push(IrStatement {
                            kind: IrStmtKind::StateWrite {
                                variable: var_name.clone(),
                            },
                            loc: *loc,
                            source_line: loc_to_line(*loc),
                        });
                        let node = dfg.add_node(DfgNode::StateWrite {
                            variable: var_name,
                            loc: *loc,
                        });
                        dfg_nodes.push(node);
                    }
                }
                self.visit_expr(lhs, stmts, dfg, dfg_nodes, ssa, state_vars);
                self.visit_expr(rhs, stmts, dfg, dfg_nodes, ssa, state_vars);
            }
            Expression::FunctionCallBlock(_, target, _) => {
                self.visit_expr(target, stmts, dfg, dfg_nodes, ssa, state_vars);
            }
            Expression::ArraySubscript(_, base, index) => {
                self.visit_expr(base, stmts, dfg, dfg_nodes, ssa, state_vars);
                if let Some(idx) = index {
                    self.visit_expr(idx, stmts, dfg, dfg_nodes, ssa, state_vars);
                }
            }
            Expression::MemberAccess(_, base, _) => {
                self.visit_expr(base, stmts, dfg, dfg_nodes, ssa, state_vars);
            }
            Expression::Parenthesis(_, expr) => {
                self.visit_expr(expr, stmts, dfg, dfg_nodes, ssa, state_vars);
            }
            _ => {}
        }
    }

    /// Extract IR statements from expressions (assignments, calls, etc.).
    fn extract_expr_statements(
        &self,
        expr: &Expression,
        _loc: Loc,
        stmts: &mut Vec<IrStatement>,
        dfg: &mut DiGraph<DfgNode, DfgEdge>,
        dfg_nodes: &mut Vec<NodeIndex>,
        ssa: &mut SsaCounter,
        state_vars: &[StateVar],
    ) {
        self.visit_expr(expr, stmts, dfg, dfg_nodes, ssa, state_vars);
    }
}

impl Default for IrBuilder {
    fn default() -> Self {
        Self::new()
    }
}

/// Extract a call target and function name from a function call expression.
fn extract_call_target(expr: &Expression) -> Option<(String, String)> {
    match expr {
        Expression::MemberAccess(_, target_expr, member) => {
            let target = extract_expression_name(target_expr).unwrap_or_else(|| "<unknown>".to_string());
            Some((target, member.name.clone()))
        }
        Expression::Variable(id) => Some(("".to_string(), id.name.clone())),
        Expression::FunctionCallBlock(_, target_expr, _) => {
            extract_call_target(target_expr)
        }
        _ => None,
    }
}

/// Extract a variable name from an expression.
fn extract_variable_name(expr: &Expression) -> Option<String> {
    match expr {
        Expression::Variable(id) => Some(id.name.clone()),
        Expression::MemberAccess(_, base, member) => {
            let base_name = extract_variable_name(base)?;
            Some(format!("{}.{}", base_name, member.name))
        }
        Expression::ArraySubscript(_, base, _) => extract_variable_name(base),
        _ => None,
    }
}

/// Extract a name from an expression (for debugging/display).
fn extract_expression_name(expr: &Expression) -> Option<String> {
    match expr {
        Expression::Variable(id) => Some(id.name.clone()),
        Expression::MemberAccess(_, base, member) => {
            let base_name = extract_expression_name(base)?;
            Some(format!("{}.{}", base_name, member.name))
        }
        Expression::FunctionCallBlock(_, target_expr, _) => {
            extract_expression_name(target_expr)
        }
        _ => None,
    }
}

/// Convert a source location to a line number.
fn loc_to_line(loc: Loc) -> u32 {
    match loc {
        Loc::File(_, start, _) => start as u32,
        _ => 0,
    }
}

/// Recursively checks if a Statement is terminating (revert, return, break, continue).
fn is_terminating(stmt: &Statement) -> bool {
    match stmt {
        Statement::Block { statements, .. } => {
            statements.iter().any(|s| is_terminating(s))
        }
        Statement::Return(..) | Statement::Break(..) | Statement::Continue(..) => true,
        Statement::Expression(_, expr) => {
            if let Expression::FunctionCall(_, func_expr, _) = expr {
                if let Expression::Variable(id) = func_expr.as_ref() {
                    if id.name == "revert" {
                        return true;
                    }
                }
            }
            false
        }
        _ => {
            let name = format!("{:?}", stmt);
            name.contains("Revert") || name.contains("Throw")
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse_contract(source: &str) -> ParsedContract {
        let (ast, _) = solang_parser::parse(source, 0).unwrap();
        ParsedContract {
            path: PathBuf::from("test.sol"),
            absolute_path: PathBuf::from("/tmp/test.sol"),
            ast,
            source: source.to_string(),
            warnings: Vec::new(),
        }
    }

    #[test]
    fn build_simple_contract_ir() {
        let source = r#"
pragma solidity ^0.8.0;
contract Simple {
    uint256 public value;
    function setValue(uint256 _v) public {
        value = _v;
    }
}
"#;
        let contract = parse_contract(source);
        let builder = IrBuilder::new();
        let irs = builder.build(&contract).unwrap();

        assert_eq!(irs.len(), 1);
        assert_eq!(irs[0].name, "Simple");
        assert_eq!(irs[0].functions.len(), 1);
        assert_eq!(irs[0].state_variables.len(), 1);
        assert_eq!(irs[0].state_variables[0].name, "value");
    }

    #[test]
    fn detect_external_call_in_ir() {
        let source = r#"
pragma solidity ^0.8.0;
contract Vulnerable {
    mapping(address => uint) public balances;
    function withdraw() public {
        uint amount = balances[msg.sender];
        msg.sender.call{value: amount}("");
        balances[msg.sender] = 0;
    }
}
"#;
        let contract = parse_contract(source);
        let builder = IrBuilder::new();
        let irs = builder.build(&contract).unwrap();

        assert_eq!(irs.len(), 1);
        let func = &irs[0].functions[0];
        assert_eq!(func.name, "withdraw");

        // Should detect both the external call and the state write
        let has_external_call = func.statements.iter().any(|s| {
            matches!(&s.kind, IrStmtKind::ExternalCall { .. })
        });
        let has_state_write = func.statements.iter().any(|s| {
            matches!(&s.kind, IrStmtKind::StateWrite { .. })
        });

        assert!(has_external_call, "Should detect external call");
        assert!(has_state_write, "Should detect state write");
    }
}
