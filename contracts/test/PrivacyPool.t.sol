// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test, console} from "forge-std/Test.sol";
import {PrivacyPool} from "../src/PrivacyPool.sol";
import {RecipientRegistry} from "../src/RecipientRegistry.sol";
import {MockVerifier} from "../src/MockVerifier.sol";
import {PoseidonT3} from "poseidon-solidity/PoseidonT3.sol";

contract PrivacyPoolTest is Test {
    PrivacyPool public pool;
    RecipientRegistry public registry;
    MockVerifier public verifier;

    address alice = makeAddr("alice");
    address bob = makeAddr("bob");

    function setUp() public {
        registry = new RecipientRegistry();
        verifier = new MockVerifier();
        pool = new PrivacyPool(address(verifier), address(verifier), address(registry));

        // Fund test accounts
        vm.deal(alice, 100 ether);
        vm.deal(bob, 100 ether);
    }

    // ==================== Registry Tests ====================

    function test_Registry_Register() public {
        bytes32 pkEnc = bytes32(uint256(123456));

        vm.prank(alice);
        registry.register(pkEnc);

        assertTrue(registry.isRegistered(alice));
        assertEq(registry.getEncryptionKey(alice), pkEnc);
    }

    function test_Registry_CannotRegisterTwice() public {
        bytes32 pkEnc1 = bytes32(uint256(123456));
        bytes32 pkEnc2 = bytes32(uint256(789012));

        vm.prank(alice);
        registry.register(pkEnc1);

        vm.prank(alice);
        vm.expectRevert("Already registered");
        registry.register(pkEnc2);
    }

    function test_Registry_CannotRegisterZero() public {
        vm.prank(alice);
        vm.expectRevert("Invalid public key");
        registry.register(bytes32(0));
    }

    // ==================== Pool Initialization Tests ====================

    function test_Pool_Initialization() public view {
        // Check constants
        assertEq(pool.TREE_DEPTH(), 20);
        assertEq(pool.ROOT_HISTORY_SIZE(), 500);
        assertEq(pool.VIRTUAL_CHAIN_ID(), 13371337);

        // Check initial state
        assertEq(pool.nextLeafIndex(), 0);

        // Check zeros are initialized
        uint256 zero0 = pool.getZero(0);
        assertEq(zero0, PoseidonT3.hash([uint256(0), uint256(0)]));

        // Check initial root
        uint256 initialRoot = pool.getLastRoot();
        assertTrue(pool.isKnownRoot(initialRoot));
    }

    // ==================== Deposit Tests ====================

    function test_Deposit_Basic() public {
        // Create a commitment: poseidon(amount, recipient, randomness)
        uint256 amount = 1 ether;
        uint256 randomness = 12345;
        uint256 commitment = _computeCommitment(amount, uint256(uint160(alice)), randomness);

        bytes memory encryptedNote = abi.encode(amount, randomness);

        vm.prank(alice);
        pool.deposit{value: amount}(commitment, encryptedNote);

        // Check leaf was inserted
        assertEq(pool.nextLeafIndex(), 1);

        // Check new root exists
        uint256 newRoot = pool.getLastRoot();
        assertTrue(pool.isKnownRoot(newRoot));
    }

    function test_Deposit_MultipleDeposits() public {
        // First deposit
        uint256 commitment1 = _computeCommitment(1 ether, uint256(uint160(alice)), 111);
        vm.prank(alice);
        pool.deposit{value: 1 ether}(commitment1, "");

        // Second deposit
        uint256 commitment2 = _computeCommitment(2 ether, uint256(uint160(bob)), 222);
        vm.prank(bob);
        pool.deposit{value: 2 ether}(commitment2, "");

        assertEq(pool.nextLeafIndex(), 2);
        assertEq(address(pool).balance, 3 ether);
    }

    function test_Deposit_RevertZeroCommitment() public {
        vm.prank(alice);
        vm.expectRevert(PrivacyPool.InvalidCommitment.selector);
        pool.deposit{value: 1 ether}(0, "");
    }

    function test_Deposit_RevertZeroValue() public {
        uint256 commitment = _computeCommitment(1 ether, uint256(uint160(alice)), 123);

        vm.prank(alice);
        vm.expectRevert(PrivacyPool.InvalidAmount.selector);
        pool.deposit{value: 0}(commitment, "");
    }

    // ==================== Transfer Tests (with MockVerifier) ====================

    function test_Transfer_WithMockVerifier() public {
        // Setup: deposit twice so we have 2 notes
        uint256 commitment1 = _computeCommitment(1 ether, uint256(uint160(alice)), 111);
        uint256 commitment2 = _computeCommitment(1 ether, uint256(uint160(alice)), 222);

        vm.startPrank(alice);
        pool.deposit{value: 1 ether}(commitment1, "");
        pool.deposit{value: 1 ether}(commitment2, "");
        vm.stopPrank();

        // Get current root
        uint256 merkleRoot = pool.getLastRoot();

        // Create output commitments
        uint256 output1 = _computeCommitment(0.5 ether, uint256(uint160(bob)), 333);
        uint256 output2 = _computeCommitment(1.5 ether, uint256(uint160(alice)), 444);

        // Create nullifiers (would be poseidon(commitment, nullifierKey) in reality)
        uint256[2] memory nullifiers = [uint256(1), uint256(2)];
        uint256[2] memory outputs = [output1, output2];
        uint256 intentNullifier = 12345;

        bytes[2] memory encryptedNotes = [bytes("note1"), bytes("note2")];

        // Call transfer (MockVerifier will accept)
        pool.transfer(
            "", // empty proof
            merkleRoot,
            nullifiers,
            outputs,
            intentNullifier,
            encryptedNotes
        );

        // Check nullifiers are spent
        assertTrue(pool.nullifierSpent(1));
        assertTrue(pool.nullifierSpent(2));
        assertTrue(pool.intentUsed(intentNullifier));

        // Check new leaves inserted
        assertEq(pool.nextLeafIndex(), 4); // 2 deposits + 2 transfer outputs
    }

    function test_Transfer_RevertDoubleSpend() public {
        // Setup deposits
        uint256 commitment1 = _computeCommitment(1 ether, uint256(uint160(alice)), 111);
        uint256 commitment2 = _computeCommitment(1 ether, uint256(uint160(alice)), 222);

        vm.startPrank(alice);
        pool.deposit{value: 1 ether}(commitment1, "");
        pool.deposit{value: 1 ether}(commitment2, "");
        vm.stopPrank();

        uint256 merkleRoot = pool.getLastRoot();
        uint256[2] memory nullifiers = [uint256(1), uint256(2)];
        uint256[2] memory outputs = [uint256(100), uint256(200)];
        bytes[2] memory notes;

        // First transfer succeeds
        pool.transfer("", merkleRoot, nullifiers, outputs, 1000, notes);

        // Second transfer with same nullifiers fails
        vm.expectRevert(PrivacyPool.NullifierAlreadySpent.selector);
        pool.transfer("", merkleRoot, nullifiers, [uint256(300), uint256(400)], 1001, notes);
    }

    // ==================== Withdrawal Tests ====================

    function test_Withdraw_WithMockVerifier() public {
        // Setup: deposit
        uint256 commitment1 = _computeCommitment(2 ether, uint256(uint160(alice)), 111);
        uint256 commitment2 = _computeCommitment(1 ether, uint256(uint160(alice)), 222);

        vm.startPrank(alice);
        pool.deposit{value: 2 ether}(commitment1, "");
        pool.deposit{value: 1 ether}(commitment2, "");
        vm.stopPrank();

        uint256 merkleRoot = pool.getLastRoot();
        uint256[2] memory nullifiers = [uint256(10), uint256(20)];
        uint256 changeCommitment = _computeCommitment(1 ether, uint256(uint160(alice)), 555);

        uint256 bobBalanceBefore = bob.balance;

        // Withdraw 2 ETH to bob, 1 ETH change back to alice
        pool.withdraw(
            "",
            merkleRoot,
            nullifiers,
            changeCommitment,
            30000, // intent nullifier
            bob, // recipient
            2 ether, // amount
            "" // encrypted change
        );

        // Check bob received ETH
        assertEq(bob.balance, bobBalanceBefore + 2 ether);

        // Check change commitment inserted
        assertEq(pool.nextLeafIndex(), 3); // 2 deposits + 1 change

        // Check nullifiers spent
        assertTrue(pool.nullifierSpent(10));
        assertTrue(pool.nullifierSpent(20));
    }

    // ==================== Admin Tests ====================

    function test_SetVerifiers() public {
        MockVerifier newVerifier = new MockVerifier();

        pool.setVerifiers(address(newVerifier), address(newVerifier));

        // No revert means success (owner is the test contract)
    }

    function test_SetVerifiers_RevertNotOwner() public {
        vm.prank(alice);
        vm.expectRevert(PrivacyPool.NotOwner.selector);
        pool.setVerifiers(address(0), address(0));
    }

    // ==================== Helpers ====================

    function _computeCommitment(
        uint256 amount,
        uint256 recipient,
        uint256 randomness
    ) internal pure returns (uint256) {
        // Note: In the real implementation, this would use PoseidonT4 for 3 inputs
        // For testing, we'll use a simple hash
        uint256 FIELD_SIZE = 21888242871839275222246405745257275088548364400416034343698204186575808495617;
        return uint256(keccak256(abi.encode(amount, recipient, randomness))) % FIELD_SIZE;
    }
}
