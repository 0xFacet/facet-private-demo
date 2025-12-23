// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Script, console} from "forge-std/Script.sol";
import {RecipientRegistry} from "../src/RecipientRegistry.sol";

/// @notice Deploy only the RecipientRegistry
contract DeployRegistryScript is Script {
    function run() external {
        uint256 deployerPrivateKey = vm.envUint("PRIVATE_KEY");
        address deployer = vm.addr(deployerPrivateKey);

        vm.startBroadcast(deployerPrivateKey);

        // Deployer is the trusted relayer for auto-registration
        RecipientRegistry registry = new RecipientRegistry(deployer);
        console.log("RecipientRegistry:", address(registry));
        console.log("Relayer:", deployer);

        vm.stopBroadcast();
    }
}
