// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 We Do Care Global
// Author: Emir Perla <emirperla96@gmail.com>  ORCID 0009-0009-8515-2727

import { describe, it, expect, beforeAll, afterAll, afterEach } from "vitest";
import { mkdirSync, rmSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { execFileSync } from "node:child_process";
import {
  createHash,
  generateKeyPairSync,
  sign,
  type KeyObject,
} from "node:crypto";
import https from "node:https";
import type { AddressInfo } from "node:net";
import { buildApp } from "../src/index";
import {
  loadMtlsConfig,
  parseClientCert,
  parseSubjectCN,
  buildCanonicalMessage,
  EphemeralStore,
  EPHEMERAL_KEY_HEADER,
  EPHEMERAL_SIGNATURE_HEADER,
  EPHEMERAL_TIMESTAMP_HEADER,
} from "../src/mtls";
import type { FastifyInstance } from "fastify";
import { openDb } from "@we-do-care/agentvault-core";
import { AgentVaultError } from "@we-do-care/agentvault-shared";

// @types/node i Node 24 runtime zaštavljaju redosled sign(algorithm, data, key).
const ed25519Sign = (key: KeyObject, data: Buffer): Buffer =>
  sign(null, data, key);

function expectReject(fn: () => unknown, code: string): void {
  let err: unknown;
  try {
    fn();
    err = null;
  } catch (e) {
    err = e;
  }
  expect(err).not.toBeNull();
  expect((err as AgentVaultError).code).toBe(code);
  expect((err as AgentVaultError).status).toBe(401);
}

const ROOT = join(tmpdir(), `agentvault-mtls-${process.pid}`);
const DB = join(ROOT, "vault.db");
const UNIT_DB = join(ROOT, "unit.db");
const PASS = "mtls-test-master-passphrase";
const ADMIN_TOKEN = "A".repeat(40);
const ADMIN_CRED = {
  token: ADMIN_TOKEN, subject: "agent://admin", tenant: "t1",
  role: "admin" as const, context: "production" as const,
};
const manifest = {
  enact: "2.0.0", vault: "1.0.0", name: "acme/tool", version: "1.0.0",
  description: "test tool",
  inputSchema: { type: "object", properties: { text: { type: "string" } }, required: ["text"] },
};
const allowPolicy = {
  id: "p-allow-agent",
  match: { tool: "acme/tool", agent_role: ["agent"], context: ["production"] },
  action: "allow" as const,
  priority: 100,
};

let app: FastifyInstance;
let port: number;
let caPem: string;
let sp1Cert: string;
let sp1Key: string;
let ephemeralKid = "";
let ephemeralPriv: KeyObject;

const caKey = join(ROOT, "ca.key");
const caCrt = join(ROOT, "ca.crt");
const serverKey = join(ROOT, "server.key");
const serverCsr = join(ROOT, "server.csr");
const serverCrt = join(ROOT, "server.crt");
const serverExt = join(ROOT, "server.ext");
const clientKey = join(ROOT, "client.key");
const clientCsr = join(ROOT, "client.csr");
const clientCrt = join(ROOT, "client.crt");
const clientExt = join(ROOT, "client.ext");

function genCert(args: string[]): void {
  execFileSync("openssl", args, { stdio: "pipe" });
}

function httpsClientOpts(withClientCert: boolean) {
  return {
    ca: caPem,
    cert: withClientCert ? sp1Cert : undefined,
    key: withClientCert ? sp1Key : undefined,
    rejectUnauthorized: true,
    servername: "localhost",
  };
}

function request(port: number, opts: {
  method: string;
  path: string;
  body?: unknown;
  headers?: Record<string, string>;
  withClientCert?: boolean;
}): Promise<{ statusCode: number; body: string; json(): any }> {
  return new Promise((resolve, reject) => {
    const payload = opts.body === undefined ? undefined : JSON.stringify(opts.body);
    const req = https.request({
      hostname: "127.0.0.1", port, method: opts.method, path: opts.path,
      ...httpsClientOpts(opts.withClientCert !== false),
      headers: {
        ...(opts.headers ?? {}),
        ...(payload ? { "content-type": "application/json", "content-length": Buffer.byteLength(payload).toString() } : {}),
      },
    }, (res) => {
      let data = "";
      res.on("data", (c) => (data += c));
      res.on("end", () => resolve({ statusCode: res.statusCode ?? 0, body: data, json: () => JSON.parse(data) }));
    });
    req.on("error", reject);
    if (payload) req.write(payload);
    req.end();
  });
}

const envSnapshot: Record<string, string | undefined> = {};
function setMtlsEnv() {
  for (const k of ["AGENTGUARD_MTLS_ENABLED", "AGENTGUARD_MTLS_CA_PATH", "AGENTGUARD_MTLS_CERT_PATH", "AGENTGUARD_MTLS_KEY_PATH", "AGENTGUARD_MTLS_PRINCIPALS"]) {
    envSnapshot[k] = process.env[k];
  }
  process.env.AGENTGUARD_MTLS_ENABLED = "true";
  process.env.AGENTGUARD_MTLS_CA_PATH = caCrt;
  process.env.AGENTGUARD_MTLS_CERT_PATH = serverCrt;
  process.env.AGENTGUARD_MTLS_KEY_PATH = serverKey;
  process.env.AGENTGUARD_MTLS_PRINCIPALS = JSON.stringify({ "agent://sp-1": { role: "agent", context: "production" } });
}
function restoreEnv() {
  for (const [k, v] of Object.entries(envSnapshot)) {
    if (v === undefined) delete process.env[k];
    else process.env[k] = v;
  }
}

describe("loadMtlsConfig", () => {
  afterEach(restoreEnv);

  it("is disabled by default", () => {
    delete process.env.AGENTGUARD_MTLS_ENABLED;
    expect(loadMtlsConfig().enabled).toBe(false);
    expect(loadMtlsConfig().toleranceSeconds).toBe(300);
  });

  it("is enabled when AGENTGUARD_MTLS_ENABLED=true", () => {
    setMtlsEnv();
    const cfg = loadMtlsConfig();
    expect(cfg.enabled).toBe(true);
    expect(cfg.caPath).toBe(caCrt);
    const principals = cfg.principals ?? {};
    expect(principals["agent://sp-1"]).toEqual({ role: "agent", context: "production" });
  });
});

describe("parseSubjectCN", () => {
  it("extracts CN from a subject object", () => {
    expect(parseSubjectCN({ subject: { CN: "agent://sp-1", O: "WDC" } })).toBe("agent://sp-1");
  });
  it("extracts CN from a subject string", () => {
    expect(parseSubjectCN({ subject: "/CN=agent-example/O=WDC" })).toBe("agent-example");
  });
  it("returns undefined when there is no CN", () => {
    expect(parseSubjectCN({ subject: { O: "WDC" } })).toBeUndefined();
    expect(parseSubjectCN(undefined)).toBeUndefined();
  });
});

describe("parseClientCert", () => {
  it("reads the URI SAN from a peer certificate", () => {
    expect(parseClientCert({ socket: { getPeerCertificate: () => ({ subjectaltname: "DNS:localhost, URI:agent://sp-1" }) } })).toBe("agent://sp-1");
  });
  it("falls back to the subject CN", () => {
    expect(parseClientCert({ socket: { getPeerCertificate: () => ({ subject: { CN: "agent://legacy" } }) } })).toBe("agent://legacy");
  });
  it("returns undefined without a certificate", () => {
    expect(parseClientCert({ socket: { getPeerCertificate: () => ({}) } })).toBeUndefined();
    expect(parseClientCert({})).toBeUndefined();
  });
});

describe("buildCanonicalMessage", () => {
  it("is deterministic and covers the body hash", () => {
    const a = buildCanonicalMessage({ kid: "k1", timestamp: "t1", method: "post", path: "/v1/execute", body: { tool: "x" } });
    const b = buildCanonicalMessage({ kid: "k1", timestamp: "t1", method: "POST", path: "/v1/execute", body: { tool: "x" } });
    expect(a).toBe(b);
    expect(a).not.toBe(buildCanonicalMessage({ kid: "k1", timestamp: "t1", method: "POST", path: "/v1/execute", body: { tool: "y" } }));
    expect(a).toContain(createHash("sha256").update(JSON.stringify({ tool: "x" })).digest("hex"));
  });
});

describe("EphemeralStore", () => {
  let db = openDb(UNIT_DB);
  let store = new EphemeralStore(db, "t1");
  const { publicKey, privateKey } = generateKeyPairSync("ed25519");
  const other = generateKeyPairSync("ed25519");
  const pem = publicKey.export({ type: "spki", format: "pem" }).toString();

  afterEach(() => {
    db.close();
    rmSync(UNIT_DB, { force: true });
    rmSync(`${UNIT_DB}-wal`, { force: true });
    rmSync(`${UNIT_DB}-shm`, { force: true });
    db = openDb(UNIT_DB);
    store = new EphemeralStore(db, "t1");
  });

  it("creates and consumes a single-use ephemeral credential", () => {
    const cred = store.create("agent://sp-1", pem, 3600);
    expect(cred.agentUri).toBe("agent://sp-1");
    expect(cred.tenant).toBe("t1");
    expect(new Date(cred.expiresAt).getTime()).toBeGreaterThan(new Date(cred.createdAt).getTime());
    const timestamp = new Date().toISOString();
    const message = buildCanonicalMessage({ kid: cred.kid, timestamp, method: "POST", path: "/v1/execute", body: { tool: "acme/tool" } });
    const signature = ed25519Sign(privateKey, Buffer.from(message)).toString("base64");
    const out = store.consume(cred.kid, signature, message);
    expect(out).toEqual({ agentUri: "agent://sp-1", tenant: "t1" });

    // Single-use: a second consumption is rejected.
    expectReject(() => store.consume(cred.kid, signature, message), "ephemeral_already_used");
  });

  it("rejects unknown, revoked, expired and tampered credentials", () => {
    const cred = store.create("agent://sp-1", pem, 3600);
    const timestamp = new Date().toISOString();
    const message = buildCanonicalMessage({ kid: cred.kid, timestamp, method: "POST", path: "/v1/execute", body: {} });
    const signature = ed25519Sign(privateKey, Buffer.from(message)).toString("base64");

    expectReject(() => store.consume("nope-kid", signature, message), "ephemeral_not_found");

    const tampered = message.slice(0, -1) + "x";
    expectReject(() => store.consume(cred.kid, signature, tampered), "ephemeral_invalid_signature");

    const wrongSig = ed25519Sign(other.privateKey, Buffer.from(message)).toString("base64");
    expectReject(() => store.consume(cred.kid, wrongSig, message), "ephemeral_invalid_signature");

    store.revoke(cred.kid);
    expectReject(() => store.consume(cred.kid, signature, message), "ephemeral_revoked");

    const expired = store.create("agent://sp-1", pem, -1);
    const expiredMsg = buildCanonicalMessage({ kid: expired.kid, timestamp, method: "POST", path: "/v1/execute", body: {} });
    const expiredSig = ed25519Sign(privateKey, Buffer.from(expiredMsg)).toString("base64");
    expectReject(() => store.consume(expired.kid, expiredSig, expiredMsg), "ephemeral_expired");
  });

  it("lists credentials per agent", () => {
    store.create("agent://sp-1", pem, 3600);
    store.create("agent://sp-2", pem, 3600);
    expect(store.list("agent://sp-1")).toHaveLength(1);
    expect(store.list()).toHaveLength(2);
  });
});

describe("mTLS + ephemeral execute (integration over real TLS)", () => {
  beforeAll(async () => {
    mkdirSync(ROOT, { recursive: true });

    // Trust anchor (CA).
    genCert(["genrsa", "-out", caKey, "2048"]);
    genCert(["req", "-new", "-x509", "-key", caKey, "-out", caCrt, "-days", "365", "-subj", "/CN=AgentVault Test CA"]);

    // Server identity (mTLS server cert, verified by the client).
    genCert(["genrsa", "-out", serverKey, "2048"]);
    genCert(["req", "-new", "-key", serverKey, "-out", serverCsr, "-subj", "/CN=localhost"]);
    writeFileSync(serverExt, "subjectAltName=DNS:localhost\nextendedKeyUsage=serverAuth\nkeyUsage=digitalSignature,keyEncipherment");
    genCert(["x509", "-req", "-in", serverCsr, "-CA", caCrt, "-CAkey", caKey, "-CAcreateserial", "-out", serverCrt, "-days", "365", "-extfile", serverExt]);

    // Agent service principal: X.509 certificate whose subject CN is the agent URI.
    genCert(["genrsa", "-out", clientKey, "2048"]);
    genCert(["req", "-new", "-key", clientKey, "-out", clientCsr, "-subj", "/CN=agent-sp-1/O=We Do Care Global"]);
    writeFileSync(clientExt, "subjectAltName=URI:agent://sp-1\nkeyUsage=digitalSignature");
    genCert(["x509", "-req", "-in", clientCsr, "-CA", caCrt, "-CAkey", caKey, "-CAcreateserial", "-out", clientCrt, "-days", "365", "-extfile", clientExt]);

    caPem = readFileSync(caCrt, "utf8");
    sp1Cert = readFileSync(clientCrt, "utf8");
    sp1Key = readFileSync(clientKey, "utf8");

    setMtlsEnv();

    app = await buildApp({ dbPath: DB, masterPassphrase: PASS, tenant: "t1", logger: false, credentials: [ADMIN_CRED] });
    await app.ready();
    await app.listen({ port: 0, host: "127.0.0.1" });
    const addr = app.server.address() as AddressInfo;
    port = typeof addr === "string" ? 0 : addr.port;

    // Seed a tool and an allow policy (Bearer admin + client cert over mTLS).
    await request(port, { method: "POST", path: "/v1/tools", body: { manifest, trust: "High", publisher: "acme" }, headers: { authorization: `Bearer ${ADMIN_TOKEN}` } });
    await request(port, { method: "POST", path: "/v1/policies", body: allowPolicy, headers: { authorization: `Bearer ${ADMIN_TOKEN}` } });
  });

  afterAll(async () => {
    await app.close();
    restoreEnv();
    for (const p of [DB, `${DB}-wal`, `${DB}-shm`, UNIT_DB, `${UNIT_DB}-wal`, `${UNIT_DB}-shm`]) {
      try { rmSync(p, { force: true }); } catch { /* not present */ }
    }
    try { rmSync(ROOT, { recursive: true, force: true }); } catch { /* Windows file locks may leave the temp dir behind */ }
  });

  it("registers an ephemeral credential from a client certificate", async () => {
    const { publicKey, privateKey } = generateKeyPairSync("ed25519");
    const pem = publicKey.export({ type: "spki", format: "pem" }).toString();
    const res = await request(port, {
      method: "POST", path: "/v1/ephemeral/credentials",
      body: { public_key_pem: pem, ttl_seconds: 300 },
    });
    expect(res.statusCode).toBe(201);
    const json = res.json();
    expect(typeof json.kid).toBe("string");
    expect(json.agent_uri).toBe("agent://sp-1");
    expect(new Date(json.expires_at).getTime()).toBeGreaterThan(Date.now());
    ephemeralKid = json.kid;
    ephemeralPriv = privateKey;
  });

  it("executes one tool call with a signed ephemeral key, then expires it", async () => {
    const timestamp = new Date().toISOString();
    const body = { tool: "acme/tool@1.0.0", arguments: { text: "hi" } };
    const message = buildCanonicalMessage({ kid: ephemeralKid, timestamp, method: "POST", path: "/v1/execute", body });
    const signature = ed25519Sign(ephemeralPriv, Buffer.from(message)).toString("base64");

    const res = await request(port, {
      method: "POST", path: "/v1/execute", body,
      headers: {
        [EPHEMERAL_KEY_HEADER]: ephemeralKid,
        [EPHEMERAL_SIGNATURE_HEADER]: signature,
        [EPHEMERAL_TIMESTAMP_HEADER]: timestamp,
      },
    });
    expect(res.statusCode).toBe(200);
    expect(res.json().status).toBe("ok");

    // Single-use: the same key cannot execute a second time.
    const replay = await request(port, {
      method: "POST", path: "/v1/execute", body,
      headers: {
        [EPHEMERAL_KEY_HEADER]: ephemeralKid,
        [EPHEMERAL_SIGNATURE_HEADER]: signature,
        [EPHEMERAL_TIMESTAMP_HEADER]: timestamp,
      },
    });
    expect(replay.statusCode).toBe(401);
    expect(replay.json()).toMatchObject({ error: "ephemeral_already_used" });
  });

  it("rejects execute without a client certificate (TLS layer)", async () => {
    const body = { tool: "acme/tool@1.0.0", arguments: {} };
    await expect(request(port, { method: "POST", path: "/v1/execute", body, withClientCert: false })).rejects.toThrow();
  });

  it("rejects execute without ephemeral credentials", async () => {
    const res = await request(port, {
      method: "POST", path: "/v1/execute",
      body: { tool: "acme/tool@1.0.0", arguments: {} },
    });
    expect(res.statusCode).toBe(401);
    expect(res.json()).toMatchObject({ error: "ephemeral_credential_required" });
  });

  it("rejects a forged ephemeral signature", async () => {
    const { publicKey } = generateKeyPairSync("ed25519");
    const { privateKey: attacker } = generateKeyPairSync("ed25519");
    const pem = publicKey.export({ type: "spki", format: "pem" }).toString();
    const reg = await request(port, {
      method: "POST", path: "/v1/ephemeral/credentials",
      body: { public_key_pem: pem, ttl_seconds: 300 },
    });
    expect(reg.statusCode).toBe(201);
    const forgedKid = reg.json().kid;
    const timestamp = new Date().toISOString();
    const body = { tool: "acme/tool@1.0.0", arguments: {} };
    const message = buildCanonicalMessage({ kid: forgedKid, timestamp, method: "POST", path: "/v1/execute", body });
    const signature = ed25519Sign(attacker, Buffer.from(message)).toString("base64");
    const res = await request(port, {
      method: "POST", path: "/v1/execute", body,
      headers: {
        [EPHEMERAL_KEY_HEADER]: forgedKid,
        [EPHEMERAL_SIGNATURE_HEADER]: signature,
        [EPHEMERAL_TIMESTAMP_HEADER]: timestamp,
      },
    });
    expect(res.statusCode).toBe(401);
    expect(res.json()).toMatchObject({ error: "ephemeral_invalid_signature" });
  });

  it("rejects an expired ephemeral credential", async () => {
    const { publicKey } = generateKeyPairSync("ed25519");
    const pem = publicKey.export({ type: "spki", format: "pem" }).toString();
    const { privateKey } = generateKeyPairSync("ed25519");
    const reg = await request(port, {
      method: "POST", path: "/v1/ephemeral/credentials",
      body: { public_key_pem: pem, ttl_seconds: -1 },
    });
    expect(reg.statusCode).toBe(201);
    const kid = reg.json().kid;
    const timestamp = new Date().toISOString();
    const body = { tool: "acme/tool@1.0.0", arguments: {} };
    const message = buildCanonicalMessage({ kid, timestamp, method: "POST", path: "/v1/execute", body });
    const signature = ed25519Sign(privateKey, Buffer.from(message)).toString("base64");
    const res = await request(port, {
      method: "POST", path: "/v1/execute", body,
      headers: {
        [EPHEMERAL_KEY_HEADER]: kid,
        [EPHEMERAL_SIGNATURE_HEADER]: signature,
        [EPHEMERAL_TIMESTAMP_HEADER]: timestamp,
      },
    });
    expect(res.statusCode).toBe(401);
    expect(res.json()).toMatchObject({ error: "ephemeral_expired" });
  });

  it("keeps the hash-chained audit chain intact with mTLS/ephemeral entries", async () => {
    const res = await request(port, {
      method: "GET", path: "/v1/audit",
      headers: { authorization: `Bearer ${ADMIN_TOKEN}` },
    });
    expect(res.statusCode).toBe(200);
    const json = res.json();
    expect(json.chain_ok).toBe(true);
    const actions = json.entries.map((e: { action: string; actor: string }) => e.action);
    expect(actions).toContain("ephemeral.credential.created");
    expect(actions).toContain("ephemeral.credential.consumed");
    expect(actions).toContain("tool.allowed");
    expect(json.entries.some((e: { actor: string }) => e.actor === "agent://sp-1")).toBe(true);
  });
});
