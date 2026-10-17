import { test } from "node:test";
import assert from "node:assert/strict";
import handler from "../api/zcash-tip.js";

// A tiny stand-in for the response object Vercel passes in.
function fakeRes() {
  const res = {
    code: 200,
    headers: {},
    body: undefined,
    setHeader(k, v) {
      res.headers[k] = v;
    },
    status(c) {
      res.code = c;
      return res;
    },
    json(b) {
      res.body = b;
      return res;
    },
  };
  return res;
}

// What the explorer returned for block 2,500,000 (trimmed to the fields we use).
function upstreamBlock(confirmations, nowSeconds = Date.now() / 1000) {
  const blockTime = Math.floor(nowSeconds - confirmations * 75);
  return {
    height: "2500000",
    confirmations,
    timestamp: String(blockTime),
  };
}

function mockFetch(impl) {
  const original = globalThis.fetch;
  globalThis.fetch = impl;
  return () => {
    globalThis.fetch = original;
  };
}

test("returns the tip as height + confirmations - 1", async () => {
  const restore = mockFetch(async () => ({ ok: true, status: 200, json: async () => upstreamBlock(1_020_108) }));
  try {
    const res = fakeRes();
    await handler({ method: "GET" }, res);
    assert.equal(res.code, 200);
    assert.equal(res.body.tip, 2_500_000 + 1_020_108 - 1);
    assert.equal(res.body.source, "api.mainnet.cipherscan.app");
    assert.match(res.headers["Cache-Control"], /s-maxage=60/);
  } finally {
    restore();
  }
});

test("refuses an answer that fails the time sanity check", async () => {
  // 1,020,108 blocks claimed, but the block is only a day old: impossible.
  const restore = mockFetch(async () => ({
    ok: true,
    status: 200,
    json: async () => ({ height: "2500000", confirmations: 1_020_108, timestamp: String(Math.floor(Date.now() / 1000) - 86400) }),
  }));
  try {
    const res = fakeRes();
    await handler({ method: "GET" }, res);
    assert.equal(res.code, 502);
    assert.equal(res.body.tip, undefined);
  } finally {
    restore();
  }
});

test("refuses malformed answers", async () => {
  for (const bad of [{}, { height: "x", confirmations: 5, timestamp: "1" }, { height: "2500000", confirmations: 0, timestamp: "1" }, { height: "2500000", confirmations: 5 }]) {
    const restore = mockFetch(async () => ({ ok: true, status: 200, json: async () => bad }));
    try {
      const res = fakeRes();
      await handler({ method: "GET" }, res);
      assert.equal(res.code, 502, JSON.stringify(bad));
    } finally {
      restore();
    }
  }
});

test("reports an upstream error status and a network failure as 502", async () => {
  let restore = mockFetch(async () => ({ ok: false, status: 503, json: async () => ({}) }));
  try {
    const res = fakeRes();
    await handler({ method: "GET" }, res);
    assert.equal(res.code, 502);
    assert.match(res.body.error, /503/);
  } finally {
    restore();
  }

  restore = mockFetch(async () => {
    throw new Error("network down");
  });
  try {
    const res = fakeRes();
    await handler({ method: "GET" }, res);
    assert.equal(res.code, 502);
  } finally {
    restore();
  }
});

test("only answers GET", async () => {
  const res = fakeRes();
  await handler({ method: "POST" }, res);
  assert.equal(res.code, 405);
  assert.equal(res.headers.Allow, "GET");
});
