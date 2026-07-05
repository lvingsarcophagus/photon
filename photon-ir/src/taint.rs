use crate::{ContractIR, DfgNode, DfgEdge};
use petgraph::graph::NodeIndex;
use petgraph::visit::EdgeRef;
use std::collections::{HashSet, VecDeque, HashMap};

/// A single taint flow path from source to sink.
#[derive(Debug, Clone)]
pub struct TaintFlow {
    /// The starting node of the taint flow (source).
    pub source_index: NodeIndex,
    /// The ending node of the taint flow (sink).
    pub sink_index: NodeIndex,
    /// The complete sequence of nodes in the DFG from source to sink.
    pub path: Vec<NodeIndex>,
}

/// Finds all taint flows in a contract's DFG from matching sources to matching sinks.
/// Only traverses DfgEdge::DataFlow and DfgEdge::TaintPropagation edges.
pub fn find_taint_flows<F1, F2>(
    ir: &ContractIR,
    is_source: F1,
    is_sink: F2,
) -> Vec<TaintFlow>
where
    F1: Fn(&DfgNode) -> bool,
    F2: Fn(&DfgNode) -> bool,
{
    let mut flows = Vec::new();
    let graph = &ir.dfg;

    // Find all potential source nodes
    let mut sources = Vec::new();
    for node_idx in graph.node_indices() {
        if let Some(node) = graph.node_weight(node_idx) {
            if is_source(node) {
                sources.push(node_idx);
            }
        }
    }

    // Run BFS from each source to find any reachable sinks
    for source in sources {
        let mut queue = VecDeque::new();
        let mut visited = HashSet::new();
        let mut parent = HashMap::new();

        queue.push_back(source);
        visited.insert(source);

        while let Some(current) = queue.pop_front() {
            if let Some(node) = graph.node_weight(current) {
                if is_sink(node) && current != source {
                    // Reconstruct path
                    let mut path = Vec::new();
                    let mut curr = current;
                    path.push(curr);
                    while let Some(&p) = parent.get(&curr) {
                        path.push(p);
                        curr = p;
                    }
                    path.reverse();

                    flows.push(TaintFlow {
                        source_index: source,
                        sink_index: current,
                        path,
                    });
                }
            }

            // Traverse outgoing edges
            for edge in graph.edges(current) {
                let follow = match edge.weight() {
                    DfgEdge::DataFlow | DfgEdge::TaintPropagation => true,
                    _ => false,
                };

                if follow {
                    let target = edge.target();
                    if visited.insert(target) {
                        parent.insert(target, current);
                        queue.push_back(target);
                    }
                }
            }
        }
    }

    flows
}
