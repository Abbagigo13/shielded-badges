import type { U64Like } from "./types.ts";

const U64_MAX = (1n << 64n) - 1n;

/** Checks a number against the prover's u64 limit and returns it as a decimal string. */
export function toU64String(input: U64Like, name: string): string {
  let n: bigint;
  if (typeof input === "bigint") {
    n = input;
  } else if (typeof input === "number") {
    if (!Number.isSafeInteger(input)) {
      throw new RangeError(`${name} must be a whole number (and a safe integer)`);
    }
    n = BigInt(input);
  } else if (typeof input === "string") {
    const t = input.trim();
    if (!/^\d+$/.test(t)) {
      throw new RangeError(`${name} must be a whole number written in decimal digits`);
    }
    n = BigInt(t);
  } else {
    throw new TypeError(`${name} must be a number, bigint or string`);
  }
  if (n < 0n || n > U64_MAX) {
    throw new RangeError(`${name} must be between 0 and 2^64 - 1`);
  }
  return n.toString();
}

/** True for exactly 64 hex characters, the size of one field element. */
export function isFieldHex(s: string): boolean {
  return /^[0-9a-fA-F]{64}$/.test(s);
}

/** True for a non-empty hex string with whole bytes. */
export function isProofHex(s: string): boolean {
  return /^(?:[0-9a-fA-F]{2})+$/.test(s);
}

/**
 * Makes a fresh random holder secret: 31 random bytes plus a zero byte, which keeps the
 * number below the field limit. It comes from the platform's secure random generator.
 */
export function generateSecret(): string {
  const bytes = new Uint8Array(31);
  globalThis.crypto.getRandomValues(bytes);
  let hex = "";
  for (const b of bytes) hex += b.toString(16).padStart(2, "0");
  return hex + "00";
}

/** Remembers which nullifiers a verifier has already accepted, per scope. */
export interface NullifierRegistry {
  has(scope: string, nullifier: string): boolean;
  add(scope: string, nullifier: string): void;
  clear(): void;
  readonly size: number;
}

export function createNullifierRegistry(): NullifierRegistry {
  const seen = new Set<string>();
  const key = (scope: string, nullifier: string) => `${scope}:${nullifier.toLowerCase()}`;
  return {
    has: (scope, nullifier) => seen.has(key(scope, nullifier)),
    add: (scope, nullifier) => {
      seen.add(key(scope, nullifier));
    },
    clear: () => seen.clear(),
    get size() {
      return seen.size;
    },
  };
}
