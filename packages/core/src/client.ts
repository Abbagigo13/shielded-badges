import { createNullifierRegistry, generateSecret, isFieldHex, isProofHex, toU64String } from "./encoding.ts";
import type { NullifierRegistry } from "./encoding.ts";
import { LEAF_COUNT } from "./types.ts";
import type {
  Backend,
  Credential,
  ProofBundle,
  ProveResult,
  ProverReply,
  U64Like,
  VerifyResult,
} from "./types.ts";

function must(reply: ProverReply): ProverReply {
  if (!reply.ok) throw new Error(reply.error ?? "the prover call failed");
  return reply;
}

// ---------------------------------------------------------------------------
// Holder: owns the secret, receives a credential, builds proofs.
// ---------------------------------------------------------------------------

export interface Holder {
  /** Loads the prover. The first call takes several seconds; later calls return at once. */
  ready(): Promise<void>;
  /**
   * DEMO ONLY. Asks the built-in simulated issuer for a credential. That issuer is handed
   * the holder's secret to build the tree leaf, which a real issuer would never be.
   */
  issueDemoCredential(opts: {
    badgeType: U64Like;
    value: U64Like;
    index: number;
  }): Promise<Credential>;
  /** Poseidon(secret, badgeType, scope) as 64 hex characters. */
  nullifier(badgeType: U64Like, scope: U64Like): Promise<string>;
  /** Builds a proof that the credential's value is at least `threshold`. */
  prove(opts: {
    credential: Credential;
    threshold: U64Like;
    scope: U64Like;
    /**
     * By default the holder refuses to build a proof for a false claim. Set this to true
     * to build one anyway, for example to show that a verifier rejects it.
     */
    allowFalseClaim?: boolean;
  }): Promise<ProveResult>;
}

/**
 * Creates a holder. The secret lives only inside this object. There is deliberately no way
 * to read it back, and it is never sent anywhere except into the prover.
 */
export function createHolder(backend: Backend, options: { secret?: string } = {}): Holder {
  const secret = options.secret ?? generateSecret();
  if (!isFieldHex(secret)) {
    throw new RangeError("secret must be exactly 64 hex characters");
  }

  return {
    async ready() {
      must(await backend.call("init", []));
    },

    async issueDemoCredential({ badgeType, value, index }) {
      if (!Number.isInteger(index) || index < 0 || index >= LEAF_COUNT) {
        throw new RangeError(`index must be a whole number from 0 to ${LEAF_COUNT - 1}`);
      }
      const badge = toU64String(badgeType, "badgeType");
      const val = toU64String(value, "value");
      const reply = must(await backend.call("demo_tree", [secret, badge, val, String(index)]));
      const [root, siblings, bits] = String(reply.result).split(";");
      return { badgeType: badge, value: val, index, root, siblings, bits };
    },

    async nullifier(badgeType, scope) {
      const badge = toU64String(badgeType, "badgeType");
      const sc = toU64String(scope, "scope");
      return String(must(await backend.call("nullifier", [secret, badge, sc])).result);
    },

    async prove({ credential, threshold, scope, allowFalseClaim = false }) {
      const thr = toU64String(threshold, "threshold");
      const sc = toU64String(scope, "scope");

      if (!allowFalseClaim && BigInt(credential.value) < BigInt(thr)) {
        throw new RangeError(
          "the credential value is below the threshold, so the proof would not verify",
        );
      }

      const reply = must(
        await backend.call("prove", [
          secret,
          credential.badgeType,
          credential.value,
          thr,
          sc,
          credential.root,
          credential.siblings,
          credential.bits,
        ]),
      );
      const nullifier = String(
        must(await backend.call("nullifier", [secret, credential.badgeType, sc])).result,
      );

      return {
        proof: String(reply.result),
        publicInputs: {
          root: credential.root,
          badgeType: credential.badgeType,
          threshold: thr,
          scope: sc,
          nullifier,
        },
        millis: reply.ms,
      };
    },
  };
}

// ---------------------------------------------------------------------------
// Verifier: checks proofs and blocks double claims.
// ---------------------------------------------------------------------------

export interface Verifier {
  /** Loads the prover's verification keys. Same cost as Holder.ready on a fresh backend. */
  ready(): Promise<void>;
  /** Checks the proof only. It never touches the nullifier registry. */
  check(bundle: ProofBundle): Promise<{ valid: boolean; millis: number }>;
  /**
   * Checks the proof, then rejects it if its nullifier was already accepted in this scope.
   * An accepted proof records its nullifier.
   */
  verify(bundle: ProofBundle): Promise<VerifyResult>;
  readonly registry: NullifierRegistry;
}

export function createVerifier(
  backend: Backend,
  options: { registry?: NullifierRegistry } = {},
): Verifier {
  const registry = options.registry ?? createNullifierRegistry();

  async function check(bundle: ProofBundle): Promise<{ valid: boolean; millis: number }> {
    // A verifier must never throw on hostile input: anything malformed is just "invalid".
    let args: string[];
    try {
      const p = bundle.publicInputs;
      if (!isProofHex(bundle.proof) || !isFieldHex(p.root) || !isFieldHex(p.nullifier)) {
        return { valid: false, millis: 0 };
      }
      args = [
        bundle.proof,
        p.root,
        toU64String(p.badgeType, "badgeType"),
        toU64String(p.threshold, "threshold"),
        toU64String(p.scope, "scope"),
        p.nullifier,
      ];
    } catch {
      return { valid: false, millis: 0 };
    }
    const reply = await backend.call("verify", args);
    return { valid: reply.ok && reply.result === true, millis: reply.ms };
  }

  return {
    registry,

    async ready() {
      must(await backend.call("init", []));
    },

    check,

    async verify(bundle) {
      const { valid, millis } = await check(bundle);
      if (!valid) return { status: "rejected_invalid", millis };

      const { scope, nullifier } = bundle.publicInputs;
      if (registry.has(scope, nullifier)) return { status: "rejected_replay", millis };

      registry.add(scope, nullifier);
      return { status: "accepted", millis };
    },
  };
}
