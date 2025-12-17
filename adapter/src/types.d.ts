// Type declarations for packages without types

declare module 'circomlibjs' {
  interface PoseidonFunction {
    (inputs: bigint[]): Uint8Array;
    F: {
      toString(val: Uint8Array): string;
    };
  }

  export function buildPoseidon(): Promise<PoseidonFunction>;
}
