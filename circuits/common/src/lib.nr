// Common library for privacy pool circuits
//
// This library provides shared functionality for transfer, withdraw,
// and other privacy pool circuits.
//
// CRITICAL: All hashing uses original Poseidon (NOT Poseidon2!)
// poseidon-solidity uses original Poseidon with specific parameters.

pub mod constants;
pub mod hashes;
pub mod scalar;
pub mod merkle;
pub mod registry;
pub mod encryption;
