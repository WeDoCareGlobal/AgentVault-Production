import { createHash, createPublicKey, timingSafeEqual } from "node:crypto";
// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 We Do Care Global
// Author: Emir Perla <emirperla96@gmail.com>  ORCID 0009-0009-8515-2727

import Fastify, { type FastifyInstance, type FastifyServerOptions } from "fastify";
import cors from "@fastify/cors";
import { openDb, ToolRegistry, newId } from "@we-do-care/agentvault-core";
import { SecretVault, AuditLedger } from "@we-do-care/agentvault-vault";
import { PolicyStore, evaluate, SlidingWindowCounter, can } from "@we-do-care/agentvault-governance";
import { Telemetry } from "@we-do-care/agentvault-telemetry";
import {
  AgentVaultError,
  BRAND,
  type Role,
  type Context,
  type TrustLevel,
  type PolicyRule,
} from "@we-do-care/agentvault-shared";
import {
  loadMtlsConfig,
  mtlsTlsOptions,
  parseClientCert,
  EphemeralStore,
  EPHEMERAL_KEY_HEADER,
  EPHEMERAL_SIGNATURE_HEADER,
  EPHEMERAL_TIMESTAMP_HEADER,
  buildCanonicalMessage,
  type MtlsConfig,
} from "./mtls.js";

export interface Credential {
  token: string; subject: string; tenant: string; role: Role; context: Context;
}

export interface ServerConfig {
  credentials: Credential[];
  dbPath: string;
  masterPassphrase: string;
  tenant?: string;
  logger?: boolean;
  mtls?: MtlsConfig;
}

const VALID_ROLES: Role[] = ["agent", "developer", "admin", "super_admin"];
const VALID_CONTEXTS: Context[] = ["production", "staging", "dev"];
const VALID_TRUST: TrustLevel[] = ["Untrusted", "Low", "Medium", "High", "System"];

/** Flat per-call cost used for budget accounting in v0.1.0. */
const COST_PER_CALL_USD = 0.0023;

export async function buildApp(cfg: ServerConfig): Promise<FastifyInstance> {
  if (!cfg.credentials?.length) throw new Error("Explicit API credentials required");
  const credentials = cfg.credentials.map(c => {
    if (c.token.length < 32 || !c.subject || !c.tenant || !VALID_ROLES.includes(c.role) || !VALID_CONTEXTS.includes(c.context)) throw new Error("Invalid API credential");
    return { ...c, digest: createHash("sha256").update(c.token).digest() };
  });
  if (new Set(credentials.map(c => c.digest.toString("hex"))).size !== credentials.length) throw new Error("Duplicate API credential");
  const db = openDb(cfg.dbPath);
  const tenant = cfg.tenant ?? "default";
  const registry = new ToolRegistry(db, tenant);
  const vault = new SecretVault(db, tenant, cfg.masterPassphrase);
  const audit = new AuditLedger(db, tenant);
  const policies = new PolicyStore(db, tenant);
  const telemetry = new Telemetry(db, tenant);
  const limiter = new SlidingWindowCounter();

  const mtls = cfg.mtls ?? loadMtlsConfig();
  const ephemeral = mtls.enabled ? new EphemeralStore(db, tenant) : null;
  const agentUris = new WeakMap<object, string>();

  const fastifyOptions: Record<string, unknown> = {
    logger: cfg.logger === false ? false : { level: "info", redact: ["req.headers.authorization"] },
  };
  if (mtls.enabled) {
    fastifyOptions.https = mtlsTlsOptions(mtls);
  }
  const app = Fastify(fastifyOptions as unknown as FastifyServerOptions);
  await app.register(cors, { origin: false });
  const principals = new WeakMap<object, Credential>();
  app.addHook("onRequest", async (req, reply) => {
    const path = req.url.split("?")[0];
    if (["/health", "/ready", "/version"].includes(path)) return;

    const isExecute = path === "/v1/execute" && req.method === "POST";
    const isEphemeralCreds = mtls.enabled && path.startsWith("/v1/ephemeral");

    if (mtls.enabled) {
      // mTLS: every request must present a client certificate signed by the
      // trusted CA (rejectUnauthorized at the TLS layer). Subject CN is the
      // agent's Service Principal identity.
      const agentUri = parseClientCert(req as { socket?: { getPeerCertificate?: () => unknown } });
      if (!agentUri) return reply.code(401).send({ error: "mtls_client_cert_required" });
      agentUris.set(req, agentUri);
    }

    if (!mtls.enabled || (!isExecute && !isEphemeralCreds)) {
      // Bearer-token auth for all paths except /v1/execute in mTLS mode
      // (ephemeral credentials take over authentication) and /v1/ephemeral/*
      // (client certificate is sufficient to manage ephemeral keys).
      const header = req.headers.authorization;
      if (!header?.startsWith("Bearer ") || header.length > 4096) return reply.code(401).send({ error: "unauthorized" });
      const digest = createHash("sha256").update(header.slice(7)).digest();
      const principal = credentials.find(c => timingSafeEqual(c.digest, digest));
      if (!principal) return reply.code(401).send({ error: "unauthorized" });
      if (principal.tenant !== tenant) return reply.code(403).send({ error: "tenant_mismatch" });
      principals.set(req, principal);
      const admin = ["admin", "super_admin"].includes(principal.role);
      if (path !== "/v1/execute" && !(req.method === "GET" && path.startsWith("/v1/tools")) && !admin) {
        return reply.code(403).send({ error: "admin_required" });
      }
    }
  });

  // mTLS + ephemeral key verification for /v1/execute runs in preHandler so
  // that req.body is already parsed and covered by the signed canonical
  // message.
  if (mtls.enabled && ephemeral) {
    app.addHook("preHandler", async (req, reply) => {
      const path = req.url.split("?")[0];
      if (path !== "/v1/execute" || req.method !== "POST") return;

      const agentUri = agentUris.get(req)!;
      const kid = (req.headers[EPHEMERAL_KEY_HEADER] as string | undefined);
      const signature = (req.headers[EPHEMERAL_SIGNATURE_HEADER] as string | undefined);
      const timestamp = (req.headers[EPHEMERAL_TIMESTAMP_HEADER] as string | undefined);
      if (!kid || !signature || !timestamp) {
        return reply.code(401).send({ error: "ephemeral_credential_required" });
      }
      const now = Date.now();
      const ts = Date.parse(timestamp);
      if (Number.isNaN(ts) || Math.abs(now - ts) > mtls.toleranceSeconds * 1000) {
        return reply.code(401).send({ error: "ephemeral_timestamp_stale" });
      }
      const { body = {} } = req;
      const message = buildCanonicalMessage({ kid, timestamp, method: req.method, path, body: body ?? {} });
      try {
        const { agentUri: consumed, tenant: credTenant } = ephemeral!.consume(kid, signature, message);
        if (consumed !== agentUri) {
          audit.append(agentUri, "ephemeral.credential.mismatch", `ephemeral:${kid}`, {
            certificate: agentUri,
            credential: consumed,
          });
          return reply.code(403).send({ error: "ephemeral_identity_mismatch" });
        }
        if (credTenant !== tenant) {
          audit.append(agentUri, "ephemeral.credential.tenant_mismatch", `ephemeral:${kid}`);
          return reply.code(403).send({ error: "tenant_mismatch" });
        }
        audit.append(agentUri, "ephemeral.credential.consumed", `ephemeral:${kid}`, {
          tool: (body as Record<string, unknown>)?.tool,
        });
        const roleCtx = mtls.principals?.[agentUri] ?? { role: "agent", context: "production" as Context };
        principals.set(req, { token: `ephemeral:${kid}`, subject: agentUri, tenant, role: roleCtx.role, context: roleCtx.context });
      } catch (err) {
        audit.append(agentUri, "ephemeral.credential.rejected", `ephemeral:${kid}`, { reason: (err as Error).message });
        throw err;
      }
    });
  }

  // ---- health ----
  app.get("/health", async () => ({ status: "ok", service: BRAND.product, version: BRAND.version }));
  app.get("/ready", async () => ({ status: "ready" }));
  app.get("/version", async () => ({ version: BRAND.version, brand: BRAND.org, orcid: BRAND.orcid }));

  // ---- tools ----
  app.get("/v1/tools", async () => ({ tools: registry.list() }));

  app.get<{ Params: { name: string; version: string } }>("/v1/tools/:name/:version", async (req, reply) => {
    const t = registry.get(decodeURIComponent(req.params.name), req.params.version);
    if (!t) return reply.code(404).send({ error: "not_found" });
    return t;
  });

  app.post<{ Body: { manifest: any; trust?: string; publisher?: string } }>("/v1/tools", async (req, reply) => {
    const trust = (req.body?.trust ?? "Medium") as TrustLevel;
    if (!VALID_TRUST.includes(trust)) {
      return reply.code(400).send({ error: "validation_error", message: `trust must be one of ${VALID_TRUST.join(", ")}` });
    }
    if (!req.body?.manifest?.name || !req.body?.manifest?.version) {
      return reply.code(400).send({ error: "validation_error", message: "manifest.name and manifest.version are required" });
    }
    const t = registry.register(req.body.manifest, trust, req.body.publisher);
    audit.append(principals.get(req)!.subject, "tool.register", `tool:${t.name}@${t.version}`, { id: t.id, trust });
    return reply.code(201).send(t);
  });

  app.delete<{ Params: { name: string; version: string } }>("/v1/tools/:name/:version", async (req, reply) => {
    const name = decodeURIComponent(req.params.name);
    const ok = registry.remove(name, req.params.version);
    if (!ok) return reply.code(404).send({ error: "not_found" });
    audit.append(principals.get(req)!.subject, "tool.remove", `tool:${name}@${req.params.version}`);
    return { status: "removed" };
  });

  // ---- secrets (metadata only; plaintext never leaves the vault) ----
  app.get("/v1/secrets", async () => ({ secrets: vault.list() }));

  app.post<{ Body: { namespace: string; key: string; value: string; scope?: string; ttlSeconds?: number } }>(
    "/v1/secrets",
    async (req, reply) => {
      const { namespace, key, value } = req.body ?? {};
      if (!namespace || !key || typeof value !== "string") {
        return reply.code(400).send({ error: "validation_error", message: "namespace, key and value are required" });
      }
      const meta = await vault.put(namespace, key, value, {
        scope: req.body.scope, ttlSeconds: req.body.ttlSeconds,
      });
      audit.append(principals.get(req)!.subject, "secret.create", `vault://${meta.namespace}/${meta.key}`, { key_version: meta.key_version });
      return reply.code(201).send(meta);
    },
  );

  app.post<{ Body: { namespace: string; key: string; value?: string } }>("/v1/secrets/rotate", async (req, reply) => {
    const { namespace, key, value } = req.body ?? {};
    if (!namespace || !key) {
      return reply.code(400).send({ error: "validation_error", message: "namespace and key are required" });
    }
    const meta = await vault.rotate(namespace, key, value);
    audit.append(principals.get(req)!.subject, "secret.rotate", `vault://${meta.namespace}/${meta.key}`, { key_version: meta.key_version });
    return meta;
  });

  app.delete<{ Body: { namespace: string; key: string } }>("/v1/secrets", async (req) => {
    const { namespace, key } = req.body ?? {};
    if (!namespace || !key) return { status: "bad_request", reason: "namespace_and_key_required" };
    const ok = vault.revoke(namespace, key);
    audit.append(principals.get(req)!.subject, "secret.revoke", `vault://${namespace}/${key}`, { removed: ok });
    return { status: ok ? "revoked" : "not_found" };
  });

  // ---- policies ----
  app.get("/v1/policies", async () => ({ policies: policies.list() }));
  app.post<{ Body: PolicyRule }>("/v1/policies", async (req, reply) => {
    if (!req.body?.id || !req.body?.action) {
      return reply.code(400).send({ error: "validation_error", message: "id and action are required" });
    }
    const rule = policies.put(req.body);
    audit.append(principals.get(req)!.subject, "policy.upsert", `policy:${rule.id}`, { priority: rule.priority ?? 100 });
    return reply.code(201).send(rule);
  });

  // ---- execute ----
  app.post<{ Body: {
    tool: string; arguments?: Record<string, unknown>;
    context?: Context; role?: Role; agentUri?: string; idempotency_key?: string;
  } }>("/v1/execute", async (req, reply) => {
    const started = Date.now();
    const {
      tool, arguments: args = {},
      context: requestedContext, role: requestedRole, agentUri: requestedAgent,
    } = req.body ?? {};

    const principal = principals.get(req)!;
    const { role, context, subject: agentUri } = principal;
    if ((requestedRole !== undefined && requestedRole !== role) ||
        (requestedContext !== undefined && requestedContext !== context) ||
        (requestedAgent !== undefined && requestedAgent !== agentUri)) {
      return reply.code(403).send({ error: "identity_override_forbidden" });
    }
    if (!tool) return reply.code(400).send({ error: "validation_error", message: "tool is required" });
    if (!VALID_ROLES.includes(role)) {
      return reply.code(400).send({ error: "validation_error", message: `role must be one of ${VALID_ROLES.join(", ")}` });
    }
    if (!VALID_CONTEXTS.includes(context)) {
      return reply.code(400).send({ error: "validation_error", message: `context must be one of ${VALID_CONTEXTS.join(", ")}` });
    }

    const [name, version] = tool.split("@");
    const registered = registry.get(name, version);
    if (!registered) return reply.code(404).send({ status: "denied", reason: "tool_not_found" });

    if (!can(role, "execute")) {
      audit.append(agentUri, "tool.denied", tool, { reason: "rbac", role });
      return reply.code(403).send({ status: "denied", reason: "rbac_denied" });
    }

    // Manifest-declared governance is enforced before the policy DSL.
    const gov = registered.manifest.governance;
    if (gov?.required_role && !gov.required_role.includes(role)) {
      audit.append(agentUri, "tool.denied", tool, { reason: "required_role", role });
      return reply.code(403).send({ status: "denied", reason: "role_not_permitted" });
    }
    if (gov?.allowed_contexts && !gov.allowed_contexts.includes(context)) {
      audit.append(agentUri, "tool.denied", tool, { reason: "context_not_allowed", context });
      return reply.code(403).send({ status: "denied", reason: "context_not_allowed" });
    }

    const key = `${agentUri}:${name}`;
    const callsLastMinute = limiter.count(key);
    const decision = evaluate(policies.list(), {
      tool: name, version: registered.version, role, context,
      callsLastMinute, callsToday: 0, costTodayUsd: 0, nowUtc: new Date(),
    });

    if (gov?.max_calls_per_minute !== undefined && callsLastMinute >= gov.max_calls_per_minute) {
      decision.decision = "deny";
      decision.reason = "manifest_rate_limit_exceeded";
    }

    if (decision.decision === "deny") {
      audit.append(agentUri, "tool.denied", tool, { reason: decision.reason, policyId: decision.policyId });
      telemetry.record({
        tool: name, version: registered.version, agentUri, provider: "internal",
        latencyMs: Date.now() - started, status: "denied", errorClass: decision.reason,
      });
      return reply.code(403).send({
        status: "denied", reason: decision.reason,
        policy_id: decision.policyId, retry_after_seconds: 30,
      });
    }

    if (decision.decision === "approval") {
      audit.append(agentUri, "tool.approval_required", tool, { policyId: decision.policyId });
      return reply.code(202).send({ status: "approval_required", reason: "approval_workflow_not_configured" });
    }
    limiter.hit(key);
    audit.append(agentUri, "tool.allowed", tool, { policyId: decision.policyId, context, role });

    // v0.1.0 executor: in-process echo. Container/gVisor sandbox lands in v0.2.0.
    const latency = Date.now() - started;
    const result = { ok: true, echo: args, tool, note: "v0.1.0 in-process executor" };

    telemetry.record({
      tool: name, version: registered.version, agentUri, provider: "internal",
      latencyMs: latency, status: "ok", costUsd: COST_PER_CALL_USD,
    });

    return {
      status: "ok",
      execution_mode: "demo_echo",
      call_id: newId(),
      result,
      latency_ms: latency,
      cost_usd: COST_PER_CALL_USD,
      governance: { policy_id: decision.policyId, decision: decision.decision, context, role },
    };
  });

  if (mtls.enabled && ephemeral) {
    app.post<{ Body: { public_key_pem: string; ttl_seconds?: number } }>(
      "/v1/ephemeral/credentials",
      async (req, reply) => {
        const agentUri = agentUris.get(req)!;
        const { public_key_pem, ttl_seconds } = req.body ?? {};
        if (!public_key_pem || typeof public_key_pem !== "string") {
          return reply.code(400).send({ error: "validation_error", message: "public_key_pem is required" });
        }
        try {
          createPublicKey(public_key_pem);
        } catch {
          return reply.code(400).send({ error: "validation_error", message: "public_key_pem is not a valid public key" });
        }
        const cred = ephemeral.create(agentUri, public_key_pem, ttl_seconds);
        audit.append(agentUri, "ephemeral.credential.created", `ephemeral:${cred.kid}`, { ttl_seconds });
        return reply.code(201).send({ kid: cred.kid, expires_at: cred.expiresAt, agent_uri: cred.agentUri });
      },
    );

    app.delete<{ Params: { kid: string } }>("/v1/ephemeral/credentials/:kid", async (req, reply) => {
      const agentUri = agentUris.get(req)!;
      const principal = principals.get(req);
      const admin = principal ? ["admin", "super_admin"].includes(principal.role) : false;
      const row = ephemeral.get(req.params.kid);
      if (!row) return reply.code(404).send({ error: "not_found" });
      if (row.agentUri !== agentUri && !admin) {
        return reply.code(403).send({ error: "forbidden" });
      }
      const ok = ephemeral.revoke(req.params.kid);
      audit.append(agentUri, "ephemeral.credential.revoked", `ephemeral:${req.params.kid}`, { removed: ok });
      return { status: ok ? "revoked" : "not_found" };
    });
  }

  // ---- audit ----
  app.get<{ Querystring: { limit?: string; offset?: string } }>("/v1/audit", async (req) => ({
    entries: audit.query(
      Math.min(Number(req.query.limit ?? 100), 1000),
      Number(req.query.offset ?? 0),
    ),
    chain_ok: audit.verifyChain().ok,
  }));

  // ---- telemetry ----
  app.get<{ Querystring: { tool?: string; agent?: string; limit?: string } }>("/v1/telemetry/query", async (req) => ({
    calls: telemetry.query({
      tool: req.query.tool, agent: req.query.agent,
      limit: Math.min(Number(req.query.limit ?? 100), 1000),
    }),
  }));

  app.get<{ Querystring: { tool?: string } }>("/v1/telemetry/summary", async (req) => ({
    summary: telemetry.summary(req.query.tool),
  }));

  app.get("/v1/telemetry/live", (req, reply) => {
    reply.raw.writeHead(200, {
      "Content-Type": "text/event-stream",
      "Cache-Control": "no-cache",
      Connection: "keep-alive",
      "X-Accel-Buffering": "no",
    });
    reply.raw.write(`event: hello\ndata: ${JSON.stringify({ brand: BRAND.product, version: BRAND.version })}\n\n`);
    const off = telemetry.on(span => {
      reply.raw.write(`event: call\ndata: ${JSON.stringify(span)}\n\n`);
    });
    const ping = setInterval(() => reply.raw.write(`: ping\n\n`), 25_000);
    req.raw.on("close", () => { clearInterval(ping); off(); });
  });

  // ---- error handler ----
  app.setErrorHandler((err, _req, reply) => {
    if (err instanceof AgentVaultError) {
      return reply.code(err.status).send({ error: err.code, message: err.message, retryable: err.retryable });
    }
    app.log.error(err);
    return reply.code(500).send({ error: "internal_error", message: "unexpected server error" });
  });

  app.addHook("onClose", async () => {
    vault.lock();
    db.close();
  });

  return app;
}
