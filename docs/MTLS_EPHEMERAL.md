# Agent mTLS + Ephemeral Credentials

AgentVault Next sada podržava **mTLS sloj pre tool izvršenja** sa **efemernim ključevima koji isteču nakon jednog tool izvršenja**, integrovanim sa AgentGuard-ovom hash-chained audit evidencijom (`packages/vault` `AuditLedger`).

## Šta radi

- **Svaki agent dobija X.509 sertifikat (Service Principal).** Klijentski sertifikat se apresenta na TLS sloju (mTLS). Identitet agenta se izvuče iz sertifikata: pretežno iz `URI:` Subject Alternativnog imena (RFC 5280, standard za servisne identitete), sa fallbackom na `subject CN`.
- **Efemerni ključevi isteču nakon jednog tool izvršenja.** Agent registruje svoj javni Ed25519 ključ (`POST /v1/ekskluzivno... /v1/ephemeral/credentials`) i dobija `kid`. Svaki poziv `/v1/execute` potpisuje kanoničku poruku (`kid|timestamp|method|path|bodyHash`) svojim privatnim ključem. Server potpis provjerava, ključ je **jednokratan** (`used_at` se postavlja pri prvom uspješnom pozivu), a ponovna upotreba, revociranost, isteklost i potpisivanje drugom ključem odbijaju se sa `401`.
- **Integracija sa AgentGuard HMAC audit logom.** Svaki događaj (kreiranje/revokacija/konzumpcija efemernog ključa, odbija, identity mismatch) se append-uje u isti hash-chained `audit_ledger` (`tool.allowed`/`tool.denied` već snabdeuje agenta po identitetu iz sertifikata), pa `chain_ok` ostaje istinit.
- **`AGENTGUARD_MTLS_ENABLED=true`** uključuje mTLS mod. Kad je onemogućen (default), server se ponaša kao ranije (samo Bearer tokeni).

## Datoteke

Kreirane:
- `packages/server/src/mtls.ts` — mTLS konfiguracija, parsiranje klijentskog sertifikata (URI SAN / CN), `EphemeralStore` (SQLite pohrana efemernih ključeva: kreiraj, dohvati, konzumiraj jednokratno, obezbeđi, listaj), kanonička poruka za potpis, Ed25519 verifikacija.
- `packages/server/test/mtls.test.ts` — 19 testa: konfiguracija, parsiranje sertifikata, `EphemeralStore` (jednokratnost, isteklost, revociranje, potpisivanje, listanje) i integracija über realnog TLS-a (openssl sertifikati, `/v1/execute` sa efemernim ključem, ponovna upotreba, potpisivanje trećom stranom, isteklost, nedostajan klijentski sertifikat, audit chain).
- `docs/MTLS_EPHEMERAL.md` — ovaj dokument.

Izmenjene:
- `packages/core/src/db.ts` — migracija dodaje tabelu `ephemeral_credentials` (+ indeksi).
- `packages/server/src/app.ts` — `ServerConfig.mtls`, Fastify HTTPS server (`requestCert`, `rejectUnauthorized`) kada je mTLS uđena, `onRequest` (verifikacija klijentskog sertifikata, Bearer auth preskočen za `/v1/execute` u mTLS modu i `/v1/ephemeral/*`), `preHandler` (verifikacija efemernog ključa nad parsiranim tijelom), rute `POST/DELETE /v1/ephemeral/credentials`, audit evidentiranje.
- `packages/cli/src/index.ts` — `doctor` prikaže `mTLS: enabled|disabled`; `serve` ispisuje `https://` kad je mTLS uđena.

## Aktivacija

### 1. Promjene okruženja

```bash
export AGENTGUARD_MTLS_ENABLED=true
export AGENTGUARD_MTLS_CA_PATH=/path/to/ca.crt        # poverljena CA koja potpisuje klijentske i server sertifikate
export AGENTGUARD_MTLS_CERT_PATH=/path/to/server.crt   # server identitet
export AGENTGUARD_MTLS_KEY_PATH=/path/to/server.key
export AGENTGUARD_MTLS_PRINCIPALS='{"agent://sp-1":{"role":"agent","context":"production"}}'  # mapira sertifikat u role/context (default: agent/production)
export AGENTGUARD_MTLS_EPHEMERAL_TOLERANCE_SECONDS=300 # tolerancija vremenske pečata (opciono)
```

### 2. Generisanje sertifikata (mTLS demo/produkcija)

```bash
cd /path/to/mtls-certs
# CA (poverljena ankora)
openssl genrsa -out ca.key 2048
openssl req -new -x509 -key ca.key -out ca.crt -days 365 -subj "/CN=AgentVault CA"

# Server identitet
openssl genrsa -out server.key 2048
openssl req -new -key server.key -out server.csr -subj "/CN=localhost"
printf "subjectAltName=DNS:localhost\nextendedKeyUsage=serverAuth\nkeyUsage=digitalSignature,keyEncipherment" > server.ext
openssl x509 -req -in server.csr -CA ca.crt -CAkey ca.key -CAcreateserial -out server.crt -days 365 -extfile server.ext

# Klijentski sertifikat agenta (Service Principal) — URI SAN nosi agent URI
openssl genrsa -out client.key 2048
openssl req -new -key client.key -out client.csr -subj "/CN=agent-sp-1/O=We Do Care Global"
printf "subjectAltName=URI:agent://sp-1\nkeyUsage=digitalSignature" > client.ext
openssl x509 -req -in client.csr -CA ca.crt -CAkey ca.key -CAcreateserial -out client.crt -days 365 -extfile client.ext
```

### 3. Pokretanje servera

```bash
export AGENTVAULT_CREDENTIALS_JSON='[{"token":"'$(python -c "import secrets;print(secrets.token_hex(20)))"'", "subject":"agent://admin", "tenant":"t1", "role":"admin", "context":"production"}]'
pnpm --filter @we-do-care/agentvault-server build
node packages/cli/dist/index.js serve
# -> https://localhost:7420 (mTLS uđena)
```

### 4. Token agenta (efemerni ključ) i izvršenje

Agent registruje svoj javni ključ (mTLS klijentski sertifikat je dovolan za autentifikaciju na ovoj putanji):

```bash
curl --cert client.crt --key client.key --cacert ca.crt \
  -X POST https://localhost:7420/v1/ephemeral/credentials \
  -H "Content-Type: application/json" \
  -d '{"public_key_pem": "-----BEGIN PUBLIC KEY-----...", "ttl_seconds": 300}'
# -> {"kid":"...","expires_at":"...","agent_uri":"agent://sp-1"}
```

Zatim svaki `/v1/execute` poziv potpiše:

```
X-Agent-Ephemeral-Key: <kid>
X-Agent-Ephemeral-Timestamp: <ISO-8601>
X-Agent-Ephemeral-Signature: <base64(Ed25519(kid\n<ts>\nPOST\n/v1/execute\n<sha256(body JSON)>))>
```

Ključ se **uništava (used_at) nakon prvog uspješnog izvršenja**; ponovna upotreba vraća `401 ephemeral_already_used`.

### 5. Pregled audit evidencije

```bash
curl --cert client.crt --key client.key --cacert ca.crt \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  https://localhost:7420/v1/audit
```

Polje `chain_ok` mora biti `true`; evidencije uključuju `ephemeral.credential.created`, `ephemeral.credential.consumed`, `tool.allowed` sa `actor: agent://sp-1`.

## Pokretanje testova

```bash
pnpm build              # gradi sve pakete (dist/)
pnpm run typecheck      # tsc preko svih paketa
pnpm --filter @we-do-care/agentvault-server test   # 38 testa (19 postojećih + 19 mTLS)
pnpm -r test            # svi testovi monorepoa
```

## Napomene

- Bez `AGENTGUARD_MTLS_ENABLED=true` ništa se ne menja za postojeće klijente (Bearer auth i dalje radi).
- Kad je mTLS uđena, svaki HTTP/TLS zahtev zahteva valjani klijentski sertifikat (TLS sloj odbija prije HTTP-a).
- `/v1/ephemeral/credentials` je zaštićen klijentskim sertifikatom (ne treba Bearer token); administracija revocira kroz istu putanju ili Bearer admin tokena.
