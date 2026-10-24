// e2e/smoke (RT-851, RT-748 slice I-9): black-box wire smoke against a real Backend-Core API.
//
// Scope: a POS-shaped sale capture, its idempotent replay, the 409 on a diverging replay,
// the read side and the auth boundary, over HTTP against the ephemeral stack that
// services/backend-core/tools/schemathesis/stack-up.sh brings up (API + Postgres + Redis, no
// Worker, no Connector, no ERPNext, no Clerk). All payloads are synthetic and test-only.
//
// recordReturn is not exercised: it is gated off by default in Backend-Core (POS_RETURNS_ENABLED,
// RT-73/RT-787), the ephemeral stack does not enable it, and changing the stack is a product change.
//
// This is NOT cross-product E2E (RT-714 / G5): it says nothing about a real or old POS build,
// RT-713 compatibility snapshots, the outbox drain, the ERP invoice leg or tenant isolation.
//
// Inputs (set by .github/workflows/e2e.yml):
//   E2E_BASE_URL       API origin, e.g. http://127.0.0.1:23100
//   E2E_ENVELOPE_FILE  file holding the throwaway pos_operator envelope written by stack-up.sh
import assert from "node:assert/strict";
import { randomUUID } from "node:crypto";
import { readFileSync } from "node:fs";
import { before, describe, test } from "node:test";

const BASE = process.env.E2E_BASE_URL;
const ENVELOPE_FILE = process.env.E2E_ENVELOPE_FILE;
assert.ok(BASE, "E2E_BASE_URL is required");
assert.ok(ENVELOPE_FILE, "E2E_ENVELOPE_FILE is required");
const ENVELOPE = readFileSync(ENVELOPE_FILE, "utf8").trim();
assert.ok(ENVELOPE.length > 0, "operator envelope file is empty");

const SALES = "/api/pos/v1/sales";

async function call(method, path, { body, key } = {}) {
  const headers = { authorization: `Bearer ${ENVELOPE}`, accept: "application/json" };
  if (body !== undefined) headers["content-type"] = "application/json";
  if (key) headers["idempotency-key"] = key;
  const res = await fetch(`${BASE}${path}`, {
    method,
    headers,
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  const text = await res.text();
  let json;
  try {
    json = text ? JSON.parse(text) : undefined;
  } catch {
    json = undefined;
  }
  return { status: res.status, headers: res.headers, json, text };
}

// A synthetic, test-only sale: 2 x 10.00 EGP, tender-unknown, no tenant product, no tracking.
function saleBody(externalId, overrides = {}) {
  return {
    sourceSystem: "pos-pulse",
    externalId,
    currencyCode: "EGP",
    posTotal: "20.00",
    occurredAt: new Date().toISOString(),
    lines: [
      {
        lineName: "e2e smoke item (synthetic, test-only)",
        unitPrice: "10.00",
        currencyCode: "EGP",
        quantity: "2",
        lineAmount: "20.00",
        unit: "pcs",
      },
    ],
    ...overrides,
  };
}

describe("e2e/smoke: Backend-Core POS sale wire", () => {
  const saleUuid = randomUUID();
  const externalId = `pos-pulse:${saleUuid}`;
  const key = `e2e-smoke-capture-${saleUuid}`;
  const body = saleBody(externalId);
  let sale;

  before(async () => {
    // Fails loudly if the stack or the envelope is not usable: an unknown sale is 404 only once
    // the envelope is accepted (401 means the envelope was rejected).
    const probe = await call("GET", `${SALES}/00000000-0000-4000-8000-000000000000`);
    assert.equal(probe.status, 404, `API not ready or envelope rejected: ${probe.status} ${probe.text}`);
  });

  test("captures a POS-shaped sale (201)", async () => {
    const res = await call("POST", SALES, { body, key });
    assert.equal(res.status, 201, res.text);
    sale = res.json;
    assert.match(sale.saleRef, /^[0-9a-f-]{36}$/);
    assert.equal(sale.sourceSystem, "pos-pulse");
    assert.equal(sale.externalId, externalId);
    assert.equal(Number(sale.posTotal), 20);
    assert.equal(sale.voided, false);
    assert.equal(sale.lines.length, 1);
  });

  test("replaying the same key and body returns the same sale, no second effect", async () => {
    const res = await call("POST", SALES, { body: saleBody(`pos-pulse:${randomUUID()}`), key: `e2e-smoke-broken-${randomUUID()}` }); // RT-851 red-path: second sale on replay
    assert.ok([200, 201].includes(res.status), res.text);
    assert.equal(res.headers.get("idempotent-replayed"), "true");
    assert.equal(res.json.saleRef, sale.saleRef);
    assert.equal(res.json.lines[0].lineRef, sale.lines[0].lineRef);
  });

  test("the same provenance under a new key resolves to the same sale", async () => {
    const res = await call("POST", SALES, { body, key: `e2e-smoke-capture-b-${saleUuid}` });
    assert.equal(res.status, 200, res.text);
    assert.equal(res.json.saleRef, sale.saleRef);
  });

  test("the same key with a different body is 409 idempotency_key_conflict", async () => {
    const changed = saleBody(externalId, {
      posTotal: "30.00",
      lines: [{ ...body.lines[0], quantity: "3", lineAmount: "30.00" }],
    });
    const res = await call("POST", SALES, { body: changed, key });
    assert.equal(res.status, 409, res.text);
    assert.match(res.text, /idempotency_key_conflict/);
  });

  test("a request without the operator envelope is 401", async () => {
    const res = await fetch(`${BASE}${SALES}/${sale.saleRef}`, { headers: { accept: "application/json" } });
    assert.equal(res.status, 401);
  });

  test("the read side shows exactly the one captured sale, not voided", async () => {
    const res = await call("GET", `${SALES}/${sale.saleRef}`);
    assert.equal(res.status, 200, res.text);
    assert.equal(res.json.saleRef, sale.saleRef);
    assert.equal(res.json.externalId, externalId);
    assert.equal(Number(res.json.posTotal), 20);
    assert.equal(res.json.voided, false);
    assert.equal(res.json.lines.length, 1);
  });
});
