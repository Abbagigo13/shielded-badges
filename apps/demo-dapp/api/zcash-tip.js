// Vercel serverless function: GET /api/zcash-tip
//
// Returns the current Zcash mainnet block height, read from a public explorer API.
// The browser only ever talks to this site's own server, never to a third party.
// It reads public chain data only. No keys, no addresses, no user data.

const UPSTREAM = "https://api.mainnet.cipherscan.app/api/block/2500000";
const SOURCE = "api.mainnet.cipherscan.app";
const SECONDS_PER_BLOCK = 75; // Zcash target block time since Blossom

export default async function handler(req, res) {
  if (req.method !== "GET") {
    res.setHeader("Allow", "GET");
    return res.status(405).json({ error: "method not allowed" });
  }

  try {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), 8000);
    const upstream = await fetch(UPSTREAM, {
      headers: { accept: "application/json" },
      signal: controller.signal,
    });
    clearTimeout(timer);

    if (!upstream.ok) {
      return res.status(502).json({ error: `upstream answered ${upstream.status}` });
    }

    // For a fixed old block the explorer reports how many blocks have been built on top of it,
    // so the chain tip is that block's height plus its confirmations, minus one.
    const block = await upstream.json();
    const height = Number(block.height);
    const confirmations = Number(block.confirmations);
    const blockTime = Number(block.timestamp);
    if (
      !Number.isSafeInteger(height) ||
      !Number.isSafeInteger(confirmations) ||
      confirmations < 1 ||
      !Number.isFinite(blockTime)
    ) {
      return res.status(502).json({ error: "unexpected answer from the upstream API" });
    }

    // Sanity check: the number of blocks since that block should match the time that has
    // passed (within 10%), so a wrong or stale answer is refused instead of passed on.
    const expected = (Date.now() / 1000 - blockTime) / SECONDS_PER_BLOCK;
    const ratio = confirmations / expected;
    if (!(ratio > 0.9 && ratio < 1.1)) {
      return res.status(502).json({ error: "the upstream answer failed a sanity check" });
    }

    const tip = height + confirmations - 1;
    res.setHeader("Cache-Control", "public, s-maxage=60, stale-while-revalidate=300");
    return res.status(200).json({ tip, source: SOURCE, fetchedAt: new Date().toISOString() });
  } catch {
    return res.status(502).json({ error: "could not reach the upstream API" });
  }
}
