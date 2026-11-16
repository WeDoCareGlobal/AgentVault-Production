// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 We Do Care Global
// Author: Emir Perla <emirperla96@gmail.com>  ORCID 0009-0009-8515-2727

import { createHash, createPublicKey, randomBytes, randomUUID, verify, type KeyObject } from "node:crypto";
import { readFileSync } from "node:fs";
import type { DB } from "@we-do-care/agentvault-core";
import type { Context, Role } from "@we-do-care/agentvault-shared";
import { AgentVaultError } from "@we-do-care/agentvault-shared";

export const MTLS_ENABLED_ENV = "AGENTGUARD_MTLS_ENABLED";
export const MTLS_CA_PATH_ENV = "AGENTGUARD_MTLS_CA_PATH";
export const MTLS_CERT_PATH_ENV = "AGENTGUARD_MTLS_CERT_PATH";
export const MTLS_KEY_PATH_ENV = "AGENTGUARD_MTLS_KEY_PATH";
export const MTLS_PRINCIPALS_ENV = "AGENTGUARD_MTLS_PRINCIPALS";
export const MTLS_TOLERANCE_ENV = "AGENTGUARD_MTLS_EPHEMERAL_TOLERANCE_SECONDS";

export const EPHEMERAL_KEY_HEADER = "x-agent-ephemeral-key";
export const EPHEMERAL_SIGNATURE_HEADER = "x-agent-ephemeral-signature";
export const EPHEMERAL_TIMESTAMP_HEADER = "x-agent-ephemeral-timestamp";

export const DEFAULT_TOLERANCE_SECONDS = 300;
export const DEFAULT_TTL_SECONDS = 86400;

export interface MtlsPrincipal {
  role: Role;
  context: Context;
}

export interface MtlsConfig {
  enabled: boolean;
  caPath?: string;
  certPath?: string;
  keyPath?: string;
  principals?: Record<string, MtlsPrincipal>;
  toleranceSeconds: number;
}

export interface EphemeralCredential {
  kid: string;
  agentUri: string;
  tenant: string;
  publicKeyPem: string;
  createdAt: string;
  expiresAt: string;
}

export interface EphemeralRow {
  kid: string;
  agentUri: string;
  tenant: string;
  publicKeyPem: string;
  createdAt: string;
  expiresAt: string;
  usedAt: string | null;
  revokedAt: string | null;
}

export function loadMtlsConfig(): MtlsConfig {
  const enabled = process.env[MTLS_ENABLED_ENV] === "true";
  const principals: Record<string, MtlsPrincipal> = {};
  const raw = process.env[MTLS_PRINCIPALS_ENV];
  if (raw) {
    try {
      Object.assign(principals, JSON.parse(raw));
    } catch {
      // Invalid principals map falls back to per-agent defaults below.
    }
  }
  return {
    enabled,
    caPath: process.env[MTLS_CA_PATH_ENV],
    certPath: process.env[MTLS_CERT_PATH_ENV],
    keyPath: process.env[MTLS_KEY_PATH_ENV],
    principals,
    toleranceSeconds: Number(process.env[MTLS_TOLERANCE_ENV]) || DEFAULT_TOLERANCE_SECONDS,
  };
}

export function readPemFile(path: string): string {
  return readFileSync(path, "utf8");
}

/** TLS options Fastify passes to `node:https` when mTLS is enabled. */
export function mtlsTlsOptions(cfg: MtlsConfig): Record<string, unknown> {
  if (!cfg.enabled) return {};
  if (!cfg.caPath || !cfg.certPath || !cfg.keyPath) {
    throw new AgentVaultError(
      "mtls_misconfigured",
      "AGENTGUARD_MTLS_ENABLED=true requires AGENTGUARD_MTLS_CA_PATH, AGENTGUARD_MTLS_CERT_PATH and AGENTGUARD_MTLS_KEY_PATH",
      500,
    );
  }
  return {
    key: readPemFile(cfg.keyPath),
    cert: readPemFile(cfg.certPath),
    ca: readPemFile(cfg.caPath),
    requestCert: true,
    rejectUnauthorized: true,
  };
}

/** Extracts the Service Principal identity (subject CN) from a peer certificate. */
export function parseSubjectCN(cert: unknown): string | undefined {
  if (!cert || typeof cert !== "object") return undefined;
  const c = cert as Record<string, unknown>;
  const subject = c["subject"];
  if (subject && typeof subject === "object" && !Array.isArray(subject)) {
    const cn = (subject as Record<string, unknown>)["CN"];
    if (typeof cn === "string" && cn.length > 0) return cn;
  }
  if (typeof subject === "string") {
    const m = subject.match(/CN\s*=\s*([^,\n/]+)/);
    if (m) return m[1].trim();
  }
  const cn = c["CN"];
  if (typeof cn === "string" && cn.length > 0) return cn;
  return undefined;
}

/** Reads the client certificate presented on the TLS socket (mTLS peer cert). */
export function parseClientCert(req: {
  socket?: { getPeerCertificate?: () => unknown };
}): string | undefined {
  const cert = req.socket?.getPeerCertificate?.();
  if (!cert) return undefined;
  // Prefer the URI Subject Alternative Name (RFC 5280), which is the
  // standards-compliant carrier for a service-principal agent URI.
  const san = (cert as Record<string, unknown>)["subjectaltname"];
  if (typeof san === "string") {
    const m = san.match(/(?:^|,\s*)URI:\s*([^\s,]+)/);
    if (m) return m[1];
  }
  return parseSubjectCN(cert);
}

export function buildCanonicalMessage(opts: {
  kid: string;
  timestamp: string;
  method: string;
  path: string;
  body: unknown;
}): string {
  const bodyHash =
    opts.body === undefined || opts.body === null
      ? createHash("sha256").update("").digest("hex")
      : createHash("sha256").update(JSON.stringify(opts.body)).digest("hex");
  return `${opts.kid}\n${opts.timestamp}\n${opts.method.toUpperCase()}\n${opts.path}\n${bodyHash}`;
}

export class EphemeralStore {
  constructor(private db: DB, private tenant = "default") {}

  create(
    agentUri: string,
    publicKeyPem: string,
    ttlSeconds: number = DEFAULT_TTL_SECONDS,
  ): EphemeralCredential {
    // validate the public key up front (Ed25519 or any PEM public key)
    createPublicKey(publicKeyPem);
    const kid = createHash("sha256")
      .update(`${agentUri}:${Date.now()}:${randomBytes(16).toString("hex")}`)
      .digest("hex");
    const createdAt = new Date().toISOString();
    const expiresAt = new Date(Date.now() + ttlSeconds * 1000).toISOString();
    this.db.prepare(
      `INSERT INTO ephemeral_credentials (id, tenant_id, agent_uri, kid, public_key_pem, created_at, expires_at)
       VALUES (?, ?, ?, ?, ?, ?, ?)`,
    ).run(randomUUID(), this.tenant, agentUri, kid, publicKeyPem, createdAt, expiresAt);
    return { kid, agentUri, tenant: this.tenant, publicKeyPem, createdAt, expiresAt };
  }

  get(kid: string): EphemeralRow | undefined {
    return this.db.prepare(
      `SELECT kid, agent_uri AS agentUri, tenant_id AS tenant, public_key_pem AS publicKeyPem,
              created_at AS createdAt, expires_at AS expiresAt, used_at AS usedAt, revoked_at AS revokedAt
       FROM ephemeral_credentials WHERE tenant_id=? AND kid=?`,
    ).get(this.tenant, kid) as EphemeralRow | undefined;
  }

  list(agentUri?: string): EphemeralRow[] {
    if (agentUri) {
      return this.db.prepare(
        `SELECT kid, agent_uri AS agentUri, tenant_id AS tenant, public_key_pem AS publicKeyPem,
                created_at AS createdAt, expires_at AS expiresAt, used_at AS usedAt, revoked_at AS revokedAt
         FROM ephemeral_credentials WHERE tenant_id=? AND agent_uri=? ORDER BY created_at DESC`,
      ).all(this.tenant, agentUri) as EphemeralRow[];
    }
    return this.db.prepare(
      `SELECT kid, agent_uri AS agentUri, tenant_id AS tenant, public_key_pem AS publicKeyPem,
              created_at AS createdAt, expires_at AS expiresAt, used_at AS usedAt, revoked_at AS revokedAt
       FROM ephemeral_credentials WHERE tenant_id=? ORDER BY created_at DESC`,
    ).all(this.tenant) as EphemeralRow[];
  }

  revoke(kid: string): boolean {
    const row = this.get(kid);
    if (!row || row.usedAt || row.revokedAt) return false;
    const r = this.db.prepare(
      `UPDATE ephemeral_credentials SET revoked_at=? WHERE kid=?`,
    ).run(new Date().toISOString(), kid);
    return r.changes > 0;
  }

  /**
   * Single-use ephemeral credential verification. Consumes the credential on
   * first successful verification so it can never be used for a second tool
   * execution.
   */
  consume(kid: string, signatureB64: string, message: string): {
    agentUri: string;
    tenant: string;
  } {
    const row = this.get(kid);
    if (!row) throw new AgentVaultError("ephemeral_not_found", "Ephemeral credential not found", 401);
    if (row.revokedAt) throw new AgentVaultError("ephemeral_revoked", "Ephemeral credential revoked", 401);
    if (new Date(row.expiresAt).getTime() <= Date.now())
      throw new AgentVaultError("ephemeral_expired", "Ephemeral credential expired", 401);
    if (row.usedAt) throw new AgentVaultError("ephemeral_already_used", "Ephemeral credential already consumed (single-use)", 401);
    let signature: Buffer;
    try {
      signature = Buffer.from(signatureB64, "base64");
    } catch {
      throw new AgentVaultError("ephemeral_invalid_signature", "Invalid signature encoding", 401);
    }
    const key = createPublicKey(row.publicKeyPem);
    const ok = verify(null, Buffer.from(message, "utf8"), key, signature);
    if (!ok) throw new AgentVaultError("ephemeral_invalid_signature", "Ephemeral signature verification failed", 401);
    this.db.prepare(`UPDATE ephemeral_credentials SET used_at=? WHERE kid=?`).run(
      new Date().toISOString(),
      kid,
    );
    return { agentUri: row.agentUri, tenant: row.tenant };
  }
}
