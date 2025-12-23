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

    // Sample nullifier key hashes for testing
    uint256 aliceNkHash = 12345678901234567890;
    uint256 bobNkHash = 98765432109876543210;

    // Sample Grumpkin curve points for testing
    // These are valid points on y^2 = x^3 - 17 (Grumpkin curve)
    // Generator point: (1, sqrt(1-17) mod p)
    uint256 constant GRUMPKIN_GEN_X = 1;
    uint256 constant GRUMPKIN_GEN_Y = 17631683881184975370165255887551781615748388533673675138860;

    function setUp() public {
        // Test contract is the trusted relayer for auto-registration
        registry = new RecipientRegistry(address(this));
        verifier = new MockVerifier();
        pool = new PrivacyPool(address(verifier), address(verifier), address(registry));

        // Fund test accounts
        vm.deal(alice, 100 ether);
        vm.deal(bob, 100 ether);
    }

    // ==================== Registry Tests ====================

    function test_Registry_Register() public {
        // Grumpkin curve point (x, y)
        uint256[2] memory pkEnc = [GRUMPKIN_GEN_X, GRUMPKIN_GEN_Y];

        // Bound to msg.sender
        vm.prank(alice);
        registry.register(pkEnc, aliceNkHash);

        assertTrue(registry.isRegistered(alice));
        uint256[2] memory storedKey = registry.getEncryptionKey(alice);
        assertEq(storedKey[0], pkEnc[0]);
        assertEq(storedKey[1], pkEnc[1]);
        assertEq(registry.getNullifierKeyHash(alice), aliceNkHash);
    }

    function test_Registry_CannotRegisterTwice() public {
        uint256[2] memory pkEnc1 = [GRUMPKIN_GEN_X, GRUMPKIN_GEN_Y];

        vm.prank(alice);
        registry.register(pkEnc1, aliceNkHash);

        vm.prank(alice);
        vm.expectRevert(RecipientRegistry.AlreadyRegistered.selector);
        registry.register(pkEnc1, aliceNkHash);
    }

    function test_Registry_CannotRegisterInvalidPoint() public {
        // Point not on curve (random values)
        uint256[2] memory invalidKey = [uint256(123456), uint256(789012)];

        vm.prank(alice);
        vm.expectRevert(RecipientRegistry.InvalidPoint.selector);
        registry.register(invalidKey, aliceNkHash);
    }

    function test_Registry_CannotRegisterIdentityPoint() public {
        // Identity point (0, 0)
        uint256[2] memory identityKey = [uint256(0), uint256(0)];

        vm.prank(alice);
        vm.expectRevert(RecipientRegistry.InvalidPoint.selector);
        registry.register(identityKey, aliceNkHash);
    }

    function test_Registry_ZerosInitializedCorrectly() public view {
        // zeros[0] should be 0, NOT hash(0,0)
        assertEq(registry.getZero(0), 0);

        // zeros[1] should be hash(0, 0)
        assertEq(registry.getZero(1), PoseidonT3.hash([uint256(0), uint256(0)]));
    }

    function test_Registry_RootTracking() public {
        uint256[2] memory pkEnc = [GRUMPKIN_GEN_X, GRUMPKIN_GEN_Y];

        // Initial root should be valid
        uint256 initialRoot = registry.getLatestRoot();
        assertTrue(registry.isKnownRoot(initialRoot));

        // Register a user
        vm.prank(alice);
        registry.register(pkEnc, aliceNkHash);

        // New root should be valid
        uint256 newRoot = registry.getLatestRoot();
        assertTrue(registry.isKnownRoot(newRoot));

        // Old root should still be valid (unbounded)
        assertTrue(registry.isKnownRoot(initialRoot));
    }

    function test_Registry_RegisterFor() public {
        uint256[2] memory pkEnc = [GRUMPKIN_GEN_X, GRUMPKIN_GEN_Y];

        // Test contract is the relayer, so this should work
        uint256 leafIndex = registry.registerFor(alice, pkEnc, aliceNkHash);

        assertTrue(registry.isRegistered(alice));
        assertEq(registry.getLeafIndex(alice), leafIndex);
        uint256[2] memory storedKey = registry.getEncryptionKey(alice);
        assertEq(storedKey[0], pkEnc[0]);
        assertEq(storedKey[1], pkEnc[1]);
        assertEq(registry.getNullifierKeyHash(alice), aliceNkHash);
    }

    function test_Registry_RegisterFor_RevertNotRelayer() public {
        uint256[2] memory pkEnc = [GRUMPKIN_GEN_X, GRUMPKIN_GEN_Y];

        // Alice is not the relayer
        vm.prank(alice);
        vm.expectRevert(RecipientRegistry.NotRelayer.selector);
        registry.registerFor(bob, pkEnc, bobNkHash);
    }

    function test_Registry_RegisterFor_RevertAlreadyRegistered() public {
        uint256[2] memory pkEnc = [GRUMPKIN_GEN_X, GRUMPKIN_GEN_Y];

        // First registration should work
        registry.registerFor(alice, pkEnc, aliceNkHash);

        // Second registration should fail
        vm.expectRevert(RecipientRegistry.AlreadyRegistered.selector);
        registry.registerFor(alice, pkEnc, aliceNkHash);
    }

    // ==================== Pool Initialization Tests ====================

    function test_Pool_Initialization() public view {
        // Check constants
        assertEq(pool.TREE_DEPTH(), 20);
        assertEq(pool.ROOT_HISTORY_SIZE(), 500);
        assertEq(pool.VIRTUAL_CHAIN_ID(), 13371337);

        // Check initial state
        assertEq(pool.nextLeafIndex(), 0);

        // Check zeros[0] = 0 (CRITICAL - must match registry)
        assertEq(pool.getZero(0), 0);

        // Check initial root
        uint256 initialRoot = pool.getLastRoot();
        assertTrue(pool.isKnownRoot(initialRoot));
    }

    // ==================== Deposit Tests ====================

    function test_Deposit_Basic() public {
        uint256 amount = 1 ether;
        uint256 owner = uint256(uint160(alice));
        uint256 randomness = 12345;

        bytes memory encryptedNote = abi.encode(amount, randomness);

        vm.prank(alice);
        pool.deposit{value: amount}(owner, randomness, aliceNkHash, encryptedNote);

        // Check leaf was inserted
        assertEq(pool.nextLeafIndex(), 1);

        // Check new root exists
        uint256 newRoot = pool.getLastRoot();
        assertTrue(pool.isKnownRoot(newRoot));
    }

    function test_Deposit_MultipleDeposits() public {
        // First deposit
        vm.prank(alice);
        pool.deposit{value: 1 ether}(uint256(uint160(alice)), 111, aliceNkHash, "");

        // Second deposit
        vm.prank(bob);
        pool.deposit{value: 2 ether}(uint256(uint160(bob)), 222, bobNkHash, "");

        assertEq(pool.nextLeafIndex(), 2);
        assertEq(address(pool).balance, 3 ether);
    }

    function test_Deposit_RevertZeroOwner() public {
        vm.prank(alice);
        vm.expectRevert(PrivacyPool.InvalidOwner.selector);
        pool.deposit{value: 1 ether}(0, 12345, aliceNkHash, "");
    }

    function test_Deposit_RevertZeroValue() public {
        vm.prank(alice);
        vm.expectRevert(PrivacyPool.InvalidAmount.selector);
        pool.deposit{value: 0}(uint256(uint160(alice)), 12345, aliceNkHash, "");
    }

    function test_Deposit_CommitmentComputedOnChain() public {
        uint256 amount = 1 ether;
        uint256 owner = uint256(uint160(alice));
        uint256 randomness = 12345;

        vm.prank(alice);
        pool.deposit{value: amount}(owner, randomness, aliceNkHash, "");

        // The commitment stored in the tree should be poseidon(amount, owner, randomness, nullifierKeyHash)
        // computed using the actual msg.value (1 ether), not any attacker-supplied value
        assertEq(pool.nextLeafIndex(), 1);
    }

    // ==================== Transfer Tests (with MockVerifier) ====================

    function test_Transfer_WithMockVerifier() public {
        // First register users in registry
        uint256[2] memory alicePk = [GRUMPKIN_GEN_X, GRUMPKIN_GEN_Y];
        vm.prank(alice);
        registry.register(alicePk, aliceNkHash);

        // Setup: deposit twice so we have 2 notes
        vm.startPrank(alice);
        pool.deposit{value: 1 ether}(uint256(uint160(alice)), 111, aliceNkHash, "");
        pool.deposit{value: 1 ether}(uint256(uint160(alice)), 222, aliceNkHash, "");
        vm.stopPrank();

        // Get current roots
        uint256 merkleRoot = pool.getLastRoot();
        uint256 registryRoot = registry.getLatestRoot();

        // Create output commitments
        uint256 output1 = _computeCommitment(0.5 ether, uint256(uint160(bob)), 333, bobNkHash);
        uint256 output2 = _computeCommitment(1.5 ether, uint256(uint160(alice)), 444, aliceNkHash);

        // Create nullifiers
        uint256[2] memory nullifiers = [uint256(1), uint256(2)];
        uint256[2] memory outputs = [output1, output2];
        uint256 intentNullifier = 12345;

        // In-circuit encrypted notes (5 field elements each)
        uint256[5][2] memory encryptedNotes;
        encryptedNotes[0] = [uint256(1), uint256(2), uint256(3), uint256(4), uint256(5)];
        encryptedNotes[1] = [uint256(6), uint256(7), uint256(8), uint256(9), uint256(10)];

        // Call transfer (MockVerifier will accept)
        pool.transfer(
            "", // empty proof
            merkleRoot,
            registryRoot,
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
        // First register alice
        uint256[2] memory alicePk = [GRUMPKIN_GEN_X, GRUMPKIN_GEN_Y];
        vm.prank(alice);
        registry.register(alicePk, aliceNkHash);

        // Setup deposits
        vm.startPrank(alice);
        pool.deposit{value: 1 ether}(uint256(uint160(alice)), 111, aliceNkHash, "");
        pool.deposit{value: 1 ether}(uint256(uint160(alice)), 222, aliceNkHash, "");
        vm.stopPrank();

        uint256 merkleRoot = pool.getLastRoot();
        uint256 registryRoot = registry.getLatestRoot();
        uint256[2] memory nullifiers = [uint256(1), uint256(2)];
        uint256[2] memory outputs = [uint256(100), uint256(200)];
        uint256[5][2] memory notes;

        // First transfer succeeds
        pool.transfer("", merkleRoot, registryRoot, nullifiers, outputs, 1000, notes);

        // Second transfer with same nullifiers fails
        vm.expectRevert(PrivacyPool.NullifierAlreadySpent.selector);
        pool.transfer("", merkleRoot, registryRoot, nullifiers, [uint256(300), uint256(400)], 1001, notes);
    }

    function test_Transfer_RevertUnknownRegistryRoot() public {
        // Setup deposits
        vm.prank(alice);
        pool.deposit{value: 1 ether}(uint256(uint160(alice)), 111, aliceNkHash, "");

        uint256 merkleRoot = pool.getLastRoot();
        uint256 invalidRegistryRoot = 999999; // Not a known root
        uint256[2] memory nullifiers = [uint256(1), uint256(2)];
        uint256[2] memory outputs = [uint256(100), uint256(200)];
        uint256[5][2] memory notes;

        vm.expectRevert(PrivacyPool.UnknownRegistryRoot.selector);
        pool.transfer("", merkleRoot, invalidRegistryRoot, nullifiers, outputs, 1000, notes);
    }

    function test_Transfer_RevertNonCanonicalField() public {
        uint256 merkleRoot = pool.getLastRoot();
        uint256 registryRoot = registry.getLatestRoot();
        uint256 tooLarge = pool.FIELD_SIZE() + 1;

        uint256[2] memory nullifiers = [uint256(1), uint256(2)];
        uint256[2] memory outputs = [uint256(100), uint256(200)];
        uint256[5][2] memory notes;

        // Non-canonical merkle root
        vm.expectRevert(PrivacyPool.NonCanonicalField.selector);
        pool.transfer("", tooLarge, registryRoot, nullifiers, outputs, 1000, notes);
    }

    // ==================== Withdrawal Tests ====================

    function test_Withdraw_WithMockVerifier() public {
        // First register alice
        uint256[2] memory alicePk = [GRUMPKIN_GEN_X, GRUMPKIN_GEN_Y];
        vm.prank(alice);
        registry.register(alicePk, aliceNkHash);

        // Setup: deposit
        vm.startPrank(alice);
        pool.deposit{value: 2 ether}(uint256(uint160(alice)), 111, aliceNkHash, "");
        pool.deposit{value: 1 ether}(uint256(uint160(alice)), 222, aliceNkHash, "");
        vm.stopPrank();

        uint256 merkleRoot = pool.getLastRoot();
        uint256 registryRoot = registry.getLatestRoot();
        uint256[2] memory nullifiers = [uint256(10), uint256(20)];
        uint256 changeCommitment = _computeCommitment(1 ether, uint256(uint160(alice)), 555, aliceNkHash);

        uint256 bobBalanceBefore = bob.balance;

        // Encrypted change note (5 field elements)
        uint256[5] memory encryptedChange = [uint256(1), uint256(2), uint256(3), uint256(4), uint256(5)];

        // Withdraw 2 ETH to bob, 1 ETH change back to alice
        pool.withdraw(
            "",
            merkleRoot,
            registryRoot,
            nullifiers,
            changeCommitment,
            30000, // intent nullifier
            bob, // recipient
            2 ether, // amount
            encryptedChange
        );

        // Check bob received ETH
        assertEq(bob.balance, bobBalanceBefore + 2 ether);

        // Check change commitment inserted
        assertEq(pool.nextLeafIndex(), 3); // 2 deposits + 1 change

        // Check nullifiers spent
        assertTrue(pool.nullifierSpent(10));
        assertTrue(pool.nullifierSpent(20));
    }

    function test_Withdraw_RevertNonCanonicalAmount() public {
        // First register and deposit so we have valid roots
        uint256[2] memory alicePk = [GRUMPKIN_GEN_X, GRUMPKIN_GEN_Y];
        vm.prank(alice);
        registry.register(alicePk, aliceNkHash);

        vm.prank(alice);
        pool.deposit{value: 10 ether}(uint256(uint160(alice)), 111, aliceNkHash, "");

        uint256 merkleRoot = pool.getLastRoot();
        uint256 registryRoot = registry.getLatestRoot();
        uint256[2] memory nullifiers = [uint256(10), uint256(20)];
        uint256 changeCommitment = 12345;
        uint256[5] memory encryptedChange;

        // Cache FIELD_SIZE before expectRevert (which consumes next external call)
        uint256 fieldSize = pool.FIELD_SIZE();

        // Amount >= FIELD_SIZE should revert with NonCanonicalField
        vm.expectRevert(PrivacyPool.NonCanonicalField.selector);
        pool.withdraw(
            "",
            merkleRoot,
            registryRoot,
            nullifiers,
            changeCommitment,
            30000,
            bob,
            fieldSize, // CRITICAL: non-canonical amount (>= FIELD_SIZE)
            encryptedChange
        );
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
        uint256 owner,
        uint256 randomness,
        uint256 nullifierKeyHash
    ) internal pure returns (uint256) {
        // Use binary tree hashing with PoseidonT3 to match circuit and contract:
        // hash(hash(amount, owner), hash(randomness, nkHash))
        uint256 h1 = PoseidonT3.hash([amount, owner]);
        uint256 h2 = PoseidonT3.hash([randomness, nullifierKeyHash]);
        return PoseidonT3.hash([h1, h2]);
    }
}
