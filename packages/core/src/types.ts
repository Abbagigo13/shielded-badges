/** Fixed by the circuit: the issuer tree has 4 levels, so it holds 16 credentials. */
export const DEPTH = 4;
export const LEAF_COUNT = 16;

/** value - threshold must fit in this many bits. */
export const RANGE_BITS = 64;

/** A whole number from 0 to 2^64 - 1, given as a number, a bigint or a decimal string. */
export type U64Like = number | bigint | string;

/** The calls the Wasm prover understands. */
export type Method = "init" | "demo_tree" | "nullifier" | "prove" | "verify";

/** One request sent to the prover (the message format used with a Web Worker). */
export interface ProverRequest {
  id: number;
  method: Method;
  args: string[];
}

/** The prover's answer to one request. */
export interface ProverReply {
  id: number;
  ok: boolean;
  result?: unknown;
  error?: string;
  /** Milliseconds the prover spent on this call. */
  ms: number;
}

/** Anything that can run prover calls: a Web Worker, or the Wasm module directly. */
export interface Backend {
  call(method: Method, args: readonly string[]): Promise<ProverReply>;
  close(): void;
}

/** The values a verifier receives. None of them reveals the secret or the credential value. */
export interface PublicInputs {
  /** Issuer Merkle root, 64 hex characters. */
  root: string;
  badgeType: string;
  threshold: string;
  scope: string;
  /** Poseidon(secret, badgeType, scope), 64 hex characters. */
  nullifier: string;
}

/** A proof plus the public inputs it was made for. This is what a holder sends. */
export interface ProofBundle {
  /** The proof as a hex string. */
  proof: string;
  publicInputs: PublicInputs;
}

/** A bundle plus how long the proof took to build. */
export interface ProveResult extends ProofBundle {
  millis: number;
}

/**
 * A credential as the holder keeps it. PRIVATE: it contains the credential value and the
 * Merkle path, so it must never be sent to a verifier.
 */
export interface Credential {
  badgeType: string;
  value: string;
  index: number;
  root: string;
  /** Four sibling hashes, comma separated hex. */
  siblings: string;
  /** Four index bits, comma separated 0 or 1. */
  bits: string;
}

export type VerifyStatus = "accepted" | "rejected_invalid" | "rejected_replay";

export interface VerifyResult {
  status: VerifyStatus;
  /** Milliseconds the verification took. */
  millis: number;
}
