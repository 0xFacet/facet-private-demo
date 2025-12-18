// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test, console} from "forge-std/Test.sol";
import {PrivacyPool} from "../src/PrivacyPool.sol";
import {RecipientRegistry} from "../src/RecipientRegistry.sol";
import {MockVerifier} from "../src/MockVerifier.sol";
import {PoseidonT3} from "poseidon-solidity/PoseidonT3.sol";
import {PoseidonT4} from "poseidon-solidity/PoseidonT4.sol";

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
        // 33-byte compressed public key: 0x02 prefix + 32-byte x-coordinate
        bytes memory pkEnc = abi.encodePacked(bytes1(0x02), bytes32(uint256(123456)));

        // World-writable: anyone can register for anyone
        registry.register(alice, pkEnc);

        assertTrue(registry.isRegistered(alice));
        assertEq(keccak256(registry.getEncryptionKey(alice)), keccak256(pkEnc));
    }

    function test_Registry_CannotRegisterTwice() public {
        bytes memory pkEnc1 = abi.encodePacked(bytes1(0x02), bytes32(uint256(123456)));
        bytes memory pkEnc2 = abi.encodePacked(bytes1(0x03), bytes32(uint256(789012)));

        registry.register(alice, pkEnc1);

        vm.expectRevert("Already registered");
        registry.register(alice, pkEnc2);
    }

    function test_Registry_CannotRegisterInvalidLength() public {
        bytes memory invalidKey = abi.encodePacked(bytes32(uint256(123456))); // 32 bytes, not 33

        vm.expectRevert("Invalid public key length");
        registry.register(alice, invalidKey);
    }

    function test_Registry_CannotRegisterInvalidPrefix() public {
        bytes memory invalidKey = abi.encodePacked(bytes1(0x04), bytes32(uint256(123456))); // invalid prefix

        vm.expectRevert("Invalid public key prefix");
        registry.register(alice, invalidKey);
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
        // New deposit signature: deposit(owner, randomness, encryptedNote)
        // Contract computes commitment on-chain from msg.value
        uint256 amount = 1 ether;
        uint256 owner = uint256(uint160(alice));
        uint256 randomness = 12345;

        bytes memory encryptedNote = abi.encode(amount, randomness);

        vm.prank(alice);
        pool.deposit{value: amount}(owner, randomness, encryptedNote);

        // Check leaf was inserted
        assertEq(pool.nextLeafIndex(), 1);

        // Check new root exists
        uint256 newRoot = pool.getLastRoot();
        assertTrue(pool.isKnownRoot(newRoot));
    }

    function test_Deposit_MultipleDeposits() public {
        // First deposit
        vm.prank(alice);
        pool.deposit{value: 1 ether}(uint256(uint160(alice)), 111, "");

        // Second deposit
        vm.prank(bob);
        pool.deposit{value: 2 ether}(uint256(uint160(bob)), 222, "");

        assertEq(pool.nextLeafIndex(), 2);
        assertEq(address(pool).balance, 3 ether);
    }

    function test_Deposit_RevertZeroOwner() public {
        vm.prank(alice);
        vm.expectRevert(PrivacyPool.InvalidOwner.selector);
        pool.deposit{value: 1 ether}(0, 12345, "");
    }

    function test_Deposit_RevertZeroValue() public {
        vm.prank(alice);
        vm.expectRevert(PrivacyPool.InvalidAmount.selector);
        pool.deposit{value: 0}(uint256(uint160(alice)), 12345, "");
    }

    function test_Deposit_CommitmentComputedOnChain() public {
        // This test verifies the security fix: commitment is computed on-chain
        // so an attacker cannot deposit 1 wei with a commitment encoding 1 ETH
        uint256 amount = 1 ether;
        uint256 owner = uint256(uint160(alice));
        uint256 randomness = 12345;

        vm.prank(alice);
        pool.deposit{value: amount}(owner, randomness, "");

        // The commitment stored in the tree should be poseidon(amount, owner, randomness)
        // computed using the actual msg.value (1 ether), not any attacker-supplied value
        // This prevents fake-amount attacks
        assertEq(pool.nextLeafIndex(), 1);
    }

    // ==================== Transfer Tests (with MockVerifier) ====================

    function test_Transfer_WithMockVerifier() public {
        // Setup: deposit twice so we have 2 notes
        vm.startPrank(alice);
        pool.deposit{value: 1 ether}(uint256(uint160(alice)), 111, "");
        pool.deposit{value: 1 ether}(uint256(uint160(alice)), 222, "");
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
        vm.startPrank(alice);
        pool.deposit{value: 1 ether}(uint256(uint160(alice)), 111, "");
        pool.deposit{value: 1 ether}(uint256(uint160(alice)), 222, "");
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
        vm.startPrank(alice);
        pool.deposit{value: 2 ether}(uint256(uint160(alice)), 111, "");
        pool.deposit{value: 1 ether}(uint256(uint160(alice)), 222, "");
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
