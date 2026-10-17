/**
 * Zcash mainnet targets one block every 75 seconds, so 1152 blocks is about one day.
 * Using the block height as the proof "scope" makes a holder's nullifier change roughly
 * once a day: a verifier can allow one claim per day, and claims on different days
 * cannot be linked to each other.
 */
export const ZCASH_BLOCKS_PER_DAY = 1152;

/** The epoch number for a Zcash block height. */
export function zcashEpoch(height: number, blocksPerEpoch: number = ZCASH_BLOCKS_PER_DAY): number {
  if (!Number.isSafeInteger(height) || height < 0) {
    throw new RangeError("height must be a whole number, 0 or more");
  }
  if (!Number.isSafeInteger(blocksPerEpoch) || blocksPerEpoch < 1) {
    throw new RangeError("blocksPerEpoch must be a whole number, 1 or more");
  }
  return Math.floor(height / blocksPerEpoch);
}

/** What the demo's /api/zcash-tip endpoint returns once checked. */
export interface ZcashTip {
  tip: number;
  epoch: number;
}

/** Checks an untrusted JSON answer from a tip endpoint and adds the epoch. Throws if it is not valid. */
export function parseZcashTip(json: unknown, blocksPerEpoch: number = ZCASH_BLOCKS_PER_DAY): ZcashTip {
  const tip = (json as { tip?: unknown } | null)?.tip;
  if (typeof tip !== "number" || !Number.isSafeInteger(tip) || tip < 0) {
    throw new TypeError("the tip answer must contain a whole-number tip height");
  }
  return { tip, epoch: zcashEpoch(tip, blocksPerEpoch) };
}
