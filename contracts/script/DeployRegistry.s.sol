// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Script, console} from "forge-std/Script.sol";
import {RecipientRegistry} from "../src/RecipientRegistry.sol";

/// @notice Deploy only the RecipientRegistry
contract DeployRegistryScript is Script {
    function run() external {
        uint256 deployerPrivateKey = vm.envUint("PRIVATE_KEY");

        vm.startBroadcast(deployerPrivateKey);

        RecipientRegistry registry = new RecipientRegistry();
        console.log("RecipientRegistry:", address(registry));

        vm.stopBroadcast();
    }
}
