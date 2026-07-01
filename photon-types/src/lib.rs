//! # photon-types
//!
//! Shared types, finding schema, severity rubric, and configuration structures
//! for the Photon Web3 Vulnerability Assessment Framework.
//!
//! This crate defines the canonical data structures used across all pipeline stages.
//! The `Finding` struct matches the reference schema from Section 6 of the design document.
//! The `AiAnnotations` struct is intentionally separated to enforce the hard boundary
//! from Section 8.4: AI output can never mutate deterministic findings.

pub mod config;
pub mod finding;
pub mod severity;

pub use config::*;
pub use finding::*;
pub use severity::*;
