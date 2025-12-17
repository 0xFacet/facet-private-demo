// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {IVerifier} from "./IVerifier.sol";

/// @title MockVerifier
/// @notice Mock verifier that always returns true (for testing)
/// @dev Replace with real verifier after circuits are compiled
contract MockVerifier is IVerifier {
    /// @notice Always returns true - DO NOT USE IN PRODUCTION
    function verify(bytes calldata, bytes32[] calldata) external view override returns (bool) {
        return true;
    }
}
