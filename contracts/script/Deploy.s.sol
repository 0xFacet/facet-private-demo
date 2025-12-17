// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Script, console} from "forge-std/Script.sol";
import {RecipientRegistry} from "../src/RecipientRegistry.sol";
import {PrivacyPool} from "../src/PrivacyPool.sol";
import {MockVerifier} from "../src/MockVerifier.sol";
import {HonkVerifier as TransferVerifier} from "../verifiers/TransferVerifier.sol";
import {WithdrawHonkVerifier as WithdrawVerifier} from "../verifiers/WithdrawVerifier.sol";

/// @notice Deploy script for Privacy Pool
contract DeployScript is Script {
    function run() external {
        uint256 deployerPrivateKey = vm.envUint("PRIVATE_KEY");
        bool useMock = vm.envOr("USE_MOCK_VERIFIER", false);

        vm.startBroadcast(deployerPrivateKey);

        // Deploy Registry
        RecipientRegistry registry = new RecipientRegistry();
        console.log("RecipientRegistry:", address(registry));

        address transferVerifier;
        address withdrawVerifier;

        if (useMock) {
            // Deploy MockVerifier (for testing)
            MockVerifier verifier = new MockVerifier();
            console.log("MockVerifier:", address(verifier));
            transferVerifier = address(verifier);
            withdrawVerifier = address(verifier);
        } else {
            // Deploy real verifiers
            TransferVerifier tv = new TransferVerifier();
            console.log("TransferVerifier:", address(tv));
            transferVerifier = address(tv);

            WithdrawVerifier wv = new WithdrawVerifier();
            console.log("WithdrawVerifier:", address(wv));
            withdrawVerifier = address(wv);
        }

        // Deploy PrivacyPool
        PrivacyPool pool = new PrivacyPool(transferVerifier, withdrawVerifier, address(registry));
        console.log("PrivacyPool:", address(pool));

        vm.stopBroadcast();

        console.log("\n=== Deployment Complete ===");
    }
}
