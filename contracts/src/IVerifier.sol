// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title IVerifier
/// @notice Interface for ZK proof verifiers (transfer and withdraw)
interface IVerifier {
    /// @notice Verify a ZK proof
    /// @param proof The proof bytes
    /// @param publicInputs The public inputs to the circuit
    /// @return True if the proof is valid
    function verify(bytes calldata proof, bytes32[] calldata publicInputs) external view returns (bool);
}
