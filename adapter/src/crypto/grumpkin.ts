// Grumpkin curve operations wrapper for bb.js
//
// Provides scalar multiplication functions for encryption/decryption.
// Uses the async Barretenberg API for curve operations.

import { Barretenberg, GRUMPKIN_G1_GENERATOR, type GrumpkinPoint } from '@aztec/bb.js';
import { Point, GRUMPKIN_GENERATOR_X, GRUMPKIN_GENERATOR_Y, FIELD_SIZE } from './embedded-curve.js';

// ========================== CONVERSION HELPERS ==========================

/**
 * Convert bigint to 32-byte big-endian Uint8Array
 */
function bigintToBytes32(n: bigint): Uint8Array {
  const hex = n.toString(16).padStart(64, '0');
  const bytes = new Uint8Array(32);
  for (let i = 0; i < 32; i++) {
    bytes[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  }
  return bytes;
}

/**
 * Convert 32-byte big-endian Uint8Array to bigint
 */
function bytes32ToBigint(bytes: Uint8Array): bigint {
  let hex = '0x';
  for (const b of bytes) {
    hex += b.toString(16).padStart(2, '0');
  }
  return BigInt(hex);
}

/**
 * Convert our Point type to bb.js GrumpkinPoint
 */
function pointToBb(p: Point): GrumpkinPoint {
  return {
    x: bigintToBytes32(p.x),
    y: bigintToBytes32(p.y),
  };
}

/**
 * Convert bb.js GrumpkinPoint to our Point type
 */
function bbToPoint(p: GrumpkinPoint): Point {
  return {
    x: bytes32ToBigint(p.x),
    y: bytes32ToBigint(p.y),
  };
}

// ========================== SINGLETON BARRETENBERG ==========================

let bbInstance: Barretenberg | null = null;
let initPromise: Promise<Barretenberg> | null = null;

/**
 * Initialize Barretenberg singleton
 * Thread-safe: multiple calls will await the same initialization
 */
export async function initGrumpkin(): Promise<void> {
  if (bbInstance) return;

  if (!initPromise) {
    initPromise = Barretenberg.new().then(async (bb) => {
      // grumpkinMul doesn't require SRS initialization
      bbInstance = bb;
      return bb;
    });
  }

  await initPromise;
}

/**
 * Get Barretenberg instance (throws if not initialized)
 */
function getBb(): Barretenberg {
  if (!bbInstance) {
    throw new Error('Grumpkin not initialized. Call initGrumpkin() first.');
  }
  return bbInstance;
}

// ========================== CURVE OPERATIONS ==========================

/**
 * Generator point for Grumpkin curve
 * G = (1, 17631683881184975370165255887551781615748388533673675138860)
 */
export const GENERATOR: Point = {
  x: GRUMPKIN_GENERATOR_X,
  y: GRUMPKIN_GENERATOR_Y,
};

/**
 * Scalar multiplication: P * s
 * @param point - Point on Grumpkin curve
 * @param scalar - Scalar value (will be reduced mod group order)
 * @returns Resulting point
 */
export async function scalarMul(point: Point, scalar: bigint): Promise<Point> {
  const bb = getBb();
  const result = await bb.grumpkinMul({
    point: pointToBb(point),
    scalar: bigintToBytes32(scalar % FIELD_SIZE),
  });
  return bbToPoint(result.point);
}

/**
 * Fixed-base scalar multiplication: G * s
 * Uses the Grumpkin generator point
 * @param scalar - Scalar value
 * @returns Resulting point
 */
export async function fixedBaseMul(scalar: bigint): Promise<Point> {
  const bb = getBb();
  const result = await bb.grumpkinMul({
    point: {
      x: GRUMPKIN_G1_GENERATOR.x,
      y: GRUMPKIN_G1_GENERATOR.y,
    },
    scalar: bigintToBytes32(scalar % FIELD_SIZE),
  });
  return bbToPoint(result.point);
}

/**
 * Synchronous wrapper types for encryption functions
 * These wrap async operations for use in contexts that need sync interfaces
 */
export interface GrumpkinOps {
  scalarMul: (point: Point, scalar: bigint) => Promise<Point>;
  fixedBaseMul: (scalar: bigint) => Promise<Point>;
}

/**
 * Get Grumpkin operations interface
 */
export function getGrumpkinOps(): GrumpkinOps {
  return {
    scalarMul,
    fixedBaseMul,
  };
}

/**
 * Verify Grumpkin is working correctly by checking generator point
 */
export async function verifyGrumpkin(): Promise<boolean> {
  try {
    // G * 1 should equal generator
    const result = await fixedBaseMul(1n);
    const matches = result.x === GENERATOR.x && result.y === GENERATOR.y;
    if (!matches) {
      console.error('[Grumpkin] Generator mismatch!');
      console.error(`  Expected: (${GENERATOR.x}, ${GENERATOR.y})`);
      console.error(`  Got: (${result.x}, ${result.y})`);
    }
    return matches;
  } catch (e) {
    console.error('[Grumpkin] Verification failed:', e);
    return false;
  }
}

/**
 * Destroy Barretenberg instance (cleanup)
 */
export async function destroyGrumpkin(): Promise<void> {
  if (bbInstance) {
    await bbInstance.destroy();
    bbInstance = null;
    initPromise = null;
  }
}
