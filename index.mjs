// CodeArts (华为云码道 代码智能体) as a magpie / OpenCode provider plugin.
//
// CodeArts, Huawei Cloud's coding agent (码道), serves its models over an
// OpenAI-compatible Chat Completions API at
// https://snap-access.cn-north-4.myhuaweicloud.com/api/v2 — but unlike a plain
// OpenAI-compatible provider it does NOT take an API key. Requests are signed
// with临时 AK/SK/security-token credentials using Huawei's SDK-HMAC-SHA256
// scheme, and those credentials are obtained by signing in to Huawei Cloud
// with OAuth.
//
// This plugin implements exactly that flow, mirroring the real CodeArts agent
// (and the `Ebony-Vinyl/dsh-our-free-model` CodeArts channel, which this plugin
// is modelled on):
//
//   1. `auth.methods[0]` is `{ type: "oauth" }`. `authorize()` starts a
//      loopback callback server on 127.0.0.1 (port >= 10000), returns the
//      Huawei Cloud portal URL for magpie to open, and completes with the
//      credentials once the browser is redirected back with an auth code.
//   2. The sign-in is PKCE: a random code_verifier is sent to the STS token
//      endpoint together with the code and the S256 challenge's pre-image. It
//      is also a DPoP flow: a fresh ES256 (P-256) key pair signs each token
//      request, and the private key JWK is persisted so refresh requests can
//      sign with it too.
//   3. STS answers with rotating AK/SK/security-token credentials plus a
//      refresh_token. The whole credential (including the verifier and DPoP
//      key) is stored as JSON in the account's `access` field.
//   4. `auth.refresh` silently renews before expiry via `grant_type =
//      refresh_token`; the same verifier and DPoP key are reused.
//   5. Every model request is signed with SDK-HMAC-SHA256 in the loader's
//      `fetch`, and the account's live model list + quota are read from
//      signed GETs.
//   6. The session headers (`Chat-Id` / `Session-Id`) are derived from the
//      account's credential, so every process and device running the same
//      account shares ONE upstream session: the gateway caps an account at 3
//      concurrent sessions keyed by `Chat-Id`. The session-limit error
//      (TM.00001041) is retried with backoff, and a 401 signature rejection
//      triggers one forced credential refresh + retry.
//
// It imitates @magpie-community/opencode-workbuddy-auth for structure but
// replaces its browser sign-in + bearer-token requests with CodeArts' OAuth +
// signed-request flow. See README.md / DESIGN.md.

import { createServer } from "node:http"
import fs from "node:fs"
import os from "node:os"
import path from "node:path"

const PROVIDER = "codearts"
const NPM = "@ai-sdk/openai-compatible" // chat completions

// ---- endpoints & flow constants --------------------------------------------

// Chat Completions base (loader `baseURL`). A chat goes to
// `${CHAT_API_BASE}/chat/completions`.
const CHAT_API_BASE = "https://snap-access.cn-north-4.myhuaweicloud.com/api/v2"
// Snap-access manager host: model list + account/quota + legacy ticket polling.
const SNAP_HOST = "https://snap-access.cn-north-4.myhuaweicloud.com"
const SNAP_MODEL_BUILTIN_URL = `${SNAP_HOST}/v1/model/builtin`
const SNAP_STATISTICS_URL = `${SNAP_HOST}/snap-manager/v1/statistics/plugin`
const CREDENTIAL_ENDPOINT = `${SNAP_HOST}/snap-manager/v1/login/ticket`
// opengw gateway config: the benefit/free-quota model set.
const OPENGW_GATEWAY_CONFIG_URL = "https://opengw.developer.huaweicloud.com/api/v1/gateway/config"
// OAuth portal (new IAM flow) and the STS token endpoint.
const PORTAL_AUTHORIZE_BASE = "https://codearts.huaweicloud.com/portal/authorize"
const PORTAL_LOGIN_BASE = "https://codearts.huaweicloud.com/portal/login"
const STS_TOKEN_ENDPOINT = "https://sts.cn-north-4.myhuaweicloud.com/v1/oauth2/tokens"

// OAuth client id (equals the plugin's URI scheme) and local callback path.
const CLIENT_ID = "codearts-agent"
const REDIRECT_PATH = "/oauth/callback"
// What the portal expects the calling plugin to be called (reverse-engineered
// constants — the plugin/version match the real IDE extension, not this package).
const LOGIN_PLUGIN_NAME = "snap_AIIDE"
const LOGIN_PLUGIN_VERSION = "5.2.0"
const OAUTH_THEME = "2" // activeColorTheme.kind: 2 = Dark
const OAUTH_LOCALE = "zh-cn"

const GRANT_AUTHORIZATION_CODE = "authorization_code"
const GRANT_REFRESH_TOKEN = "refresh_token"

const TOKEN_TIMEOUT_MS = 60_000
const REQUEST_TIMEOUT_MS = 30_000
const OAUTH_CALLBACK_TIMEOUT_MS = 180_000
const MIN_CALLBACK_PORT = 10_000
const LOGIN_POLL_ATTEMPTS = 120

// Renew this long before the credential expires.
const REFRESH_LEAD_MS = 30 * 60 * 1000

const CORS_HEADERS = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
  "Access-Control-Allow-Headers": "Content-Type, Authorization, X-Requested-With",
  "Access-Control-Max-Age": "86400",
}

// Benefits (free-quota) models require `maas_type: benefit` as a *signed*
// header, or the backend answers InferHub.002002009.404 "model is not
// registered". The authoritative list comes from opengw gateway/config at
// runtime; these are the known defaults so a cold start still works.
const BENEFIT_MODEL_FALLBACK = ["glm-5.3-flash", "deepseek-v4.1-flash"]
let benefitModelIds = [...BENEFIT_MODEL_FALLBACK]

// The upstream caps an account at 3 CONCURRENT SESSIONS and answers every
// further STREAMING request with HTTP 400 TM.00001041 ("并发会话数已达上限
// (3个)"). A streaming session keeps its slot for ~60 s after its response
// finishes, while a non-streaming request takes no slot at all (measured:
// 3 rapid `stream: true` calls then the 4th rejected for 59 s; 6 rapid
// `stream: false` calls all 200). Agents stream every turn, so an agent that
// asks three times within a minute used to be bricked.
//
// The plugin therefore keeps its own slot ledger: a streaming request waits
// for a free slot, and a TM.00001041 that still leaks through — another client
// on the same account holds the slots — is retried with backoff.
//
// Waiting the full 60 s would blow every agent's request deadline, so a
// request that cannot get a slot within SESSION_WAIT_MS is downgraded to a
// NON-streaming call (which takes no slot and is answered at once) and handed
// back to the caller as a one-shot SSE body: same content, no incremental
// chunks. A short turn pays nothing, a burst degrades gracefully instead of
// failing, and the next turn streams normally again once slots free up.
const SESSION_LIMIT_ERROR = "TM.00001041"
// The temporary AK/SK/security-token went stale (IAM rejects the call).
const STALE_TOKEN_ERROR = "APIG.0602"
// The account is out of credits. The gateway answers HTTP 200 and puts the
// error in the body — in an SSE frame when streaming — so without this a
// caller sees a successful, empty reply and has no idea why.
const QUOTA_ERROR = "InferHub.4291.200"
// The gateway refuses a bigger output budget (RANGE_VALIDATOR: max_completion
// tokens must be between 0 and 65536). Declaring no limit made callers pass
// their own default, which is over it.
const MAX_OUTPUT_TOKENS = 65_536
// Thinking must be asked for EXPLICITLY: left to the default, the gateway
// streams the model's reasoning inside `content` itself, so a caller shows the
// thinking as the answer. With `thinking: { type: "enabled" }` the reasoning
// goes to `reasoning_content` and `content` carries only the reply (measured:
// default -> content and reasoning both "我们需要回答…"; enabled -> content
// "1+1等于2。", reasoning kept apart).
const ENABLE_THINKING = { type: "enabled" }
const SESSION_SLOTS = 3
// How long the gateway keeps a finished streaming session occupied.
const SESSION_HOLD_MS = 60_000
// After the ledger says a slot is free, let it overshoot a little.
const SESSION_SLOT_MARGIN_MS = 800
// How long a streaming request waits before taking the non-streaming route.
// Short on purpose: a degraded call still has to pay its own round trip, and
// agent clients cut the whole request off at ~15 s.
const SESSION_WAIT_MS = 6_000
// Even polling rather than a long-tail exponential curve: slots free on their
// own within a minute or so, and a client deadline should catch a poll.
const SESSION_RETRY_DELAYS_MS = [1_000, 2_000, 4_000, 6_000, 8_000, 10_000, 12_000, 15_000]

// Context windows (in tokens), keyed by the exact chat model id. Models
// without an entry leave the window to the backend's default.
const CONTEXT_WINDOWS = {
  "GLM-5.2": 202752,
  "glm-5.3-flash": 1048576,
  "deepseek-v4-flash": 1048576,
  "deepseek-v4-pro": 1048576,
  "deepseek-v4.1-flash": 1000000,
}

// The models offered before (or instead of) the account's own live list.
const CATALOG = [
  { id: "GLM-5.2", name: "GLM-5.2" },
  { id: "GLM-5.1", name: "GLM-5.1" },
  { id: "GLM-5", name: "GLM-5" },
  { id: "glm-5.3-flash", name: "GLM-5.3 Flash" },
  { id: "openpangu-2.0-flash", name: "openPangu 2.0 Flash" },
  { id: "openpangu-2.0-pro", name: "openPangu 2.0 Pro" },
  { id: "deepseek-v4-flash", name: "DeepSeek V4 Flash" },
  { id: "deepseek-v4-pro", name: "DeepSeek V4 Pro" },
  { id: "deepseek-v4.1-flash", name: "DeepSeek V4.1 Flash" },
]

// ---- small helpers ---------------------------------------------------------

const firstOf = (...vs) => vs.find((v) => typeof v === "string" && v.trim())?.trim() ?? ""

const asRecord = (v) => (typeof v === "object" && v !== null && !Array.isArray(v) ? v : {})

function safeJson(text) {
  try {
    const parsed = JSON.parse(text)
    return typeof parsed === "object" && parsed !== null ? parsed : null
  } catch {
    return null
  }
}

function num(v) {
  if (typeof v === "number" && Number.isFinite(v)) return v
  if (typeof v === "string" && v.trim()) {
    const n = Number(v)
    if (Number.isFinite(n)) return n
  }
  return 0
}

const clamp = (n) => Math.max(0, Math.min(100, n))

// prettify is a model id as a name: openpangu-2.0-flash -> "Openpangu 2.0 Flash"
function prettify(id) {
  return String(id)
    .split(/[-_]/)
    .filter(Boolean)
    .map((w) => w.charAt(0).toUpperCase() + w.slice(1))
    .join(" ")
}

// stripDateSuffix drops a trailing 4-digit version tag: deepseek-v4-flash-0731
// -> deepseek-v4-flash. gateway/config lists dated ids but the chat endpoint
// only accepts the undated id.
function normalizeModelId(id) {
  if (typeof id === "string" && id.length > 5) {
    const suffix = id.slice(-5)
    if (suffix.startsWith("-") && /^\d{4}$/.test(suffix.slice(1))) return id.slice(0, -5)
  }
  return id
}

// ---- WebCrypto primitives --------------------------------------------------

function subtle() {
  const c = globalThis.crypto
  if (!c?.subtle) throw new Error("CodeArts: WebCrypto (globalThis.crypto.subtle) is unavailable")
  return c.subtle
}

const typed = (u8) => (u8 instanceof Uint8Array ? u8 : new Uint8Array(u8))

function randomBytes(n) {
  const out = new Uint8Array(n)
  globalThis.crypto.getRandomValues(out)
  return out
}

const hex = (u8) => Array.from(u8).map((b) => b.toString(16).padStart(2, "0")).join("")

function randomHex(n) {
  return hex(randomBytes(n))
}

function b64url(u8) {
  let s = ""
  for (const b of u8) s += String.fromCharCode(b)
  return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "")
}

const utf8 = (s) => new TextEncoder().encode(s)

async function sha256Hex(data) {
  const digest = await subtle().digest("SHA-256", typed(data))
  return hex(new Uint8Array(digest))
}

async function hmacSha256Hex(key, data) {
  const cryptoKey = await subtle().importKey(
    "raw", typed(key), { name: "HMAC", hash: "SHA-256" }, false, ["sign"],
  )
  const sig = await subtle().sign("HMAC", cryptoKey, typed(data))
  return hex(new Uint8Array(sig))
}

/** PKCE pair: a random 48-byte base64url verifier + its S256 challenge. */
async function generatePkcePair() {
  const codeVerifier = b64url(randomBytes(48))
  const digest = await subtle().digest("SHA-256", utf8(codeVerifier))
  return { codeVerifier, codeChallenge: b64url(new Uint8Array(digest)) }
}

/** Generate an ES256 (P-256) DPoP key pair as JWKs. */
async function generateDpopKeyPair() {
  const pair = await subtle().generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"])
  const jwk = await subtle().exportKey("jwk", pair.privateKey)
  return {
    privateKeyJwk: { kty: "EC", crv: "P-256", x: jwk.x, y: jwk.y, d: jwk.d },
    publicKeyJwk: { kty: "EC", crv: "P-256", x: jwk.x, y: jwk.y },
  }
}

/** Recover a DPoP key pair from a persisted private JWK. */
function keyPairFromStoredJwk(jwk) {
  return {
    privateKeyJwk: { kty: "EC", crv: "P-256", x: jwk.x, y: jwk.y, d: jwk.d },
    publicKeyJwk: { kty: "EC", crv: "P-256", x: jwk.x, y: jwk.y },
  }
}

/** Sign a `dpop+jwt` proof (htm=method, htu=URL) with the DPoP private key. */
async function signDpopJws(keyPair, htm, htu) {
  const header = { alg: "ES256", typ: "dpop+jwt", jwk: keyPair.publicKeyJwk }
  const payload = { htm, htu, iat: Math.floor(Date.now() / 1000), jti: randomHex(32) }
  const signingInput = `${b64url(utf8(JSON.stringify(header)))}.${b64url(utf8(JSON.stringify(payload)))}`
  const key = await subtle().importKey(
    "jwk", keyPair.privateKeyJwk, { name: "ECDSA", namedCurve: "P-256" }, false, ["sign"],
  )
  const sig = await subtle().sign({ name: "ECDSA", hash: "SHA-256" }, key, utf8(signingInput))
  // WebCrypto ECDSA returns raw r||s, which is exactly the JWS ES256 format.
  return `${signingInput}.${b64url(new Uint8Array(sig))}`
}

// ---- Huawei SDK-HMAC-SHA256 request signing --------------------------------

function buildCanonicalRequest(method, uri, query, headers, payloadHash) {
  const signedHeaders = [...headers.keys()].sort()
  const headerLines = signedHeaders.map((k) => `${k}:${headers.get(k) ?? ""}`)
  return [method, uri, query, headerLines.join("\n"), "", signedHeaders.join(";"), payloadHash].join("\n")
}

/**
 * Sign a Huawei request; returns the header map to merge into the request.
 * Extra headers (e.g. `maas_type: benefit`) participate in the canonical
 * request and must be sent verbatim, or the server rejects the signature.
 */
async function signRequestHuawei(ak, sk, securityToken, method, urlStr, body, extraHeaders, dateStampOverride) {
  const url = new URL(urlStr)
  let uri = url.pathname
  if (!uri.endsWith("/")) uri += "/"
  const query = url.search.slice(1)
  const dateStamp = dateStampOverride
    ?? new Date().toISOString().replace(/[-:]/g, "").replace(/\.\d+Z$/, "Z")
  const payloadHash = await sha256Hex(body)

  const headers = new Map()
  headers.set("host", url.host)
  headers.set("x-sdk-date", dateStamp)
  headers.set("x-sdk-content-sha256", payloadHash)
  headers.set("x-security-token", securityToken)
  if (extraHeaders !== undefined) {
    for (const [k, v] of Object.entries(extraHeaders)) headers.set(k, v)
  }
  if (method.toUpperCase() !== "GET") headers.set("content-type", "application/json")

  const signedHeaders = [...headers.keys()].sort()
  const canonicalRequest = buildCanonicalRequest(method.toUpperCase(), uri, query, headers, payloadHash)
  const canonicalHash = await sha256Hex(utf8(canonicalRequest))
  const stringToSign = `SDK-HMAC-SHA256\n${dateStamp}\n${canonicalHash}`
  const signature = await hmacSha256Hex(utf8(sk), utf8(stringToSign))
  headers.set(
    "Authorization",
    `SDK-HMAC-SHA256 Access=${ak},SignedHeaders=${signedHeaders.join(";")},Signature=${signature}`,
  )
  return headers
}

// ---- OAuth token exchange --------------------------------------------------

/** Normalize an STS token response into a persisted CodeArts credential. */
function credentialFromTokenResponse(token, codeVerifier, keyPair) {
  const c = token?.credentials ?? {}
  return {
    access_key_id: c.access_key_id ?? "",
    secret_access_key: c.secret_access_key ?? "",
    security_token: c.security_token ?? "",
    expires_at: c.expiration ?? "",
    refresh_token: token?.refresh_token,
    code_verifier: codeVerifier,
    dpop_private_key_jwk: keyPair.privateKeyJwk,
  }
}

/** The credential a sign-in carries; magpie keeps it in the `access` field. */
function credentialOf(auth) {
  if (!auth || auth.type !== "oauth") return null
  const raw = typeof auth.access === "string" ? auth.access : ""
  if (!raw) return null
  const cred = safeJson(raw)
  return cred && typeof cred.access_key_id === "string" && cred.access_key_id ? cred : null
}

function expiresFromCredential(cred) {
  if (cred?.expires_at) {
    const parsed = Date.parse(cred.expires_at)
    if (!Number.isNaN(parsed)) return parsed
  }
  return Date.now() + 86_400_000
}

/** POST the STS token endpoint with a DPoP proof. */
async function requestToken(body, keyPair, fetcher) {
  const dpop = await signDpopJws(keyPair, "POST", STS_TOKEN_ENDPOINT)
  let response
  try {
    response = await fetcher(STS_TOKEN_ENDPOINT, {
      method: "POST",
      headers: { DPoP: dpop, "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams(body).toString(),
      signal: AbortSignal.timeout(TOKEN_TIMEOUT_MS),
    })
  } catch (e) {
    throw new Error(`CodeArts token request network error: ${String(e)}`)
  }
  let data = null
  try {
    data = await response.json()
  } catch {
    data = null
  }
  if (!response.ok || !data?.credentials) {
    const message = `CodeArts token request failed: ${response.status}${data ? ` ${JSON.stringify(data)}` : ""}`
    // Only refresh_token invalidation is terminal; a transient DPoP rejection
    // must not permanently mark the account.
    const errorCode = String(data?.error_code ?? "")
    if (data?.error === "invalid_grant" || errorCode.includes("ExpiredRefreshToken")) {
      throw Object.assign(new Error(message), { signIn: "expired" })
    }
    throw new Error(message)
  }
  return data
}

function exchangeAuthorizationCode(code, codeVerifier, port, keyPair, fetcher) {
  return requestToken({
    client_id: CLIENT_ID,
    code,
    code_verifier: codeVerifier,
    grant_type: GRANT_AUTHORIZATION_CODE,
    redirect_uri: `http://127.0.0.1:${port}${REDIRECT_PATH}`,
  }, keyPair, fetcher)
}

function exchangeRefreshToken(refreshToken, codeVerifier, keyPair, fetcher) {
  return requestToken({
    client_id: CLIENT_ID,
    code_verifier: codeVerifier,
    grant_type: GRANT_REFRESH_TOKEN,
    refresh_token: refreshToken,
  }, keyPair, fetcher)
}

/** Refresh a stored credential, reusing its verifier + DPoP private key. */
async function refreshCredential(cred, fetcher) {
  const refreshToken = firstOf(cred.refresh_token)
  if (!refreshToken || !cred.code_verifier || !cred.dpop_private_key_jwk) {
    throw new Error("CodeArts: credential cannot be refreshed (missing refresh_token/code_verifier/dpop key)")
  }
  const keyPair = keyPairFromStoredJwk(cred.dpop_private_key_jwk)
  const token = await exchangeRefreshToken(refreshToken, cred.code_verifier, keyPair, fetcher)
  const next = credentialFromTokenResponse(token, cred.code_verifier, keyPair)
  if (!next.refresh_token) next.refresh_token = refreshToken
  // Preserve non-rotating identity fields a legacy login may have carried.
  for (const k of ["domain_id", "user_id", "user_name"]) {
    if (cred[k] && !next[k]) next[k] = cred[k]
  }
  return next
}

/**
 * Who signed in, so magpie recognises a re-login as the SAME account instead of
 * opening a new `codearts#<slot>` every time. The STS answer carries no user
 * fields — its refresh_token is a JWT whose `user_profile` claim holds them.
 */
function accountIdentityOf(cred) {
  const token = typeof cred?.refresh_token === "string" ? cred.refresh_token : ""
  if (token.split(".").length !== 3) return ""
  try {
    const part = token.split(".")[1].replace(/-/g, "+").replace(/_/g, "/")
    const payload = safeJson(atob(part + "=".repeat((4 - (part.length % 4)) % 4)))
    const profile = typeof payload?.user_profile === "string"
      ? safeJson(atob(payload.user_profile.replace(/-/g, "+").replace(/_/g, "/") + "=".repeat((4 - (payload.user_profile.length % 4)) % 4)))
      : payload?.user_profile
    return firstOf(profile?.principal_urn, profile?.account_name, profile?.account_id)
  } catch {
    return ""
  }
}

// ---- OAuth login: URL + loopback callback ----------------------------------

/** Build the Huawei Cloud portal authorize URL (params mirror the real IDE). */
function buildOAuthLoginUrl(port, pkce, ticketId) {
  return `${PORTAL_AUTHORIZE_BASE}?theme=${OAUTH_THEME}&locale=${OAUTH_LOCALE}`
    + `&uri_scheme=${CLIENT_ID}&client_id=${CLIENT_ID}&port=${port}`
    + `&code_challenge=${pkce.codeChallenge}&code_challenge_method=SHA-256`
    + `&ticket_id=${ticketId}&plugin-name=${LOGIN_PLUGIN_NAME}&plugin-version=${LOGIN_PLUGIN_VERSION}`
}

const buildPortalLoginResultUrl = (ok) =>
  `${PORTAL_LOGIN_BASE}?login_succeed=${ok}&uri_scheme=${CLIENT_ID}&locale=${OAUTH_LOCALE}`

/** Normalize a legacy ticket/credential response. */
function parseLegacyCredential(data) {
  const cred = data?.credential
  if (cred) {
    const ak = cred.access ?? ""
    const st = cred.securitytoken ?? cred.securityToken ?? ""
    if (ak && st) {
      return {
        access_key_id: ak,
        secret_access_key: cred.secret ?? "",
        security_token: st,
        expires_at: cred.expires_at ?? cred.expiresAt ?? "",
        domain_id: data.domain_id ?? "",
        user_id: data.user_id ?? "",
        user_name: data.user_name ?? "",
      }
    }
  }
  const r = data?.result
  if (r) {
    const ak = r.accessKeyId ?? ""
    const st = r.securityToken ?? ""
    if (ak && st) {
      return {
        access_key_id: ak,
        secret_access_key: r.secretAccessKey ?? "",
        security_token: st,
        expires_at: r.expiration ?? r.expiresAt ?? "",
      }
    }
  }
  return null
}

/** Poll the legacy ticket endpoint until a credential arrives. */
async function pollForCredential(ticketId, secret, fetcher) {
  const url = `${CREDENTIAL_ENDPOINT}?ticket_id=${encodeURIComponent(ticketId)}&secret=${encodeURIComponent(secret)}`
  for (let i = 0; i < LOGIN_POLL_ATTEMPTS; i++) {
    if (i > 0) await new Promise((r) => setTimeout(r, 1000))
    let res
    try {
      res = await fetcher(url, {
        method: "GET",
        headers: {
          "Content-Type": "application/json;charset=UTF-8",
          "plugin-name": LOGIN_PLUGIN_NAME,
          "plugin-version": LOGIN_PLUGIN_VERSION,
        },
      })
    } catch {
      continue
    }
    if (!res.ok) continue
    let data = null
    try {
      data = await res.json()
    } catch {
      continue
    }
    const cred = data ? parseLegacyCredential(data) : null
    if (cred) return cred
  }
  throw new Error("CodeArts login timed out")
}

/** Start the loopback callback server, listening on 127.0.0.1:port>=10000. */
function startOAuthCallbackServer(ticketId, pkce, keyPair, fetcher) {
  let resolveResult
  let rejectResult
  const result = new Promise((resolve, reject) => {
    resolveResult = resolve
    rejectResult = reject
  })

  const server = createServer((request, response) => {
    const url = new URL(request.url ?? "/", `http://127.0.0.1:${request.socket.localPort}`)
    if (url.pathname !== REDIRECT_PATH && !url.pathname.startsWith(REDIRECT_PATH)) {
      response.writeHead(404).end("Not found")
      return
    }
    if (request.method === "OPTIONS") {
      response.writeHead(204, CORS_HEADERS).end()
      return
    }
    const done = (cred) => resolveResult({ access: JSON.stringify(cred), expires: expiresFromCredential(cred) })

    // Legacy fallback: the portal decided OAuth is unavailable and redirected
    // with a secret; poll the ticket endpoint in the background.
    const callbackSecret = url.searchParams.get("secret")
    if (callbackSecret) {
      const redirectTo = url.searchParams.get("redirect") ?? buildPortalLoginResultUrl(true)
      response.writeHead(307, { ...CORS_HEADERS, Location: redirectTo }).end()
      void pollForCredential(ticketId, callbackSecret, fetcher).then(done, rejectResult)
      return
    }
    // New IAM OAuth: an authorization code to exchange at STS.
    const code = url.searchParams.get("code")
    if (code) {
      const port = request.socket.localPort ?? 0
      void exchangeAuthorizationCode(code, pkce.codeVerifier, port, keyPair, fetcher).then(
        (token) => {
          response.writeHead(307, { ...CORS_HEADERS, Location: buildPortalLoginResultUrl(true) }).end()
          done(credentialFromTokenResponse(token, pkce.codeVerifier, keyPair))
        },
        (error) => {
          response.writeHead(307, { ...CORS_HEADERS, Location: buildPortalLoginResultUrl(false) }).end()
          rejectResult(error)
        },
      )
      return
    }
    response.writeHead(400).end("Missing authorization code or secret")
  })

  return listenOnCallbackPort(server).then((port) => ({ port, server, result }))
}

/** Listen on 127.0.0.1, retrying with a random port >= 10000 if needed. */
function listenOnCallbackPort(server) {
  return new Promise((resolve, reject) => {
    const tryListen = (port) => {
      server.once("error", reject)
      server.listen(port, "127.0.0.1", () => {
        const address = server.address()
        const assigned = typeof address === "object" && address ? address.port : 0
        if (assigned >= MIN_CALLBACK_PORT) {
          resolve(assigned)
          return
        }
        server.close(() => tryListen(Math.floor(Math.random() * (65_536 - MIN_CALLBACK_PORT)) + MIN_CALLBACK_PORT))
      })
    }
    tryListen(0)
  })
}

/**
 * Start an OAuth flow and return its login URL immediately (magpie opens it).
 * The result resolves once the browser is redirected back and STS answers;
 * the callback server is closed as soon as the result settles.
 */
async function startOAuthFlow(fetcher) {
  const ticketId = randomHex(32)
  const pkce = await generatePkcePair()
  const keyPair = await generateDpopKeyPair()
  const { port, server, result } = await startOAuthCallbackServer(ticketId, pkce, keyPair, fetcher)
  const loginUrl = buildOAuthLoginUrl(port, pkce, ticketId)

  let closed = false
  const close = async () => {
    if (closed) return
    closed = true
    await new Promise((resolve) => server.close(() => resolve()))
  }

  const resultWithUrl = Promise.race([
    result,
    new Promise((_, reject) => {
      const timer = setTimeout(() => reject(new Error("CodeArts OAuth login timed out")), OAUTH_CALLBACK_TIMEOUT_MS)
      timer.unref?.()
    }),
  ]).then((outcome) => ({ ...outcome, loginUrl }))

  // Settle in the background so an early result never becomes an unhandled
  // rejection, and so the listening socket is always released.
  resultWithUrl.catch(() => {}).finally(() => { void close() })

  return { loginUrl, result: resultWithUrl, close }
}

// ---- signed requests to CodeArts -------------------------------------------

/** Turn a request body (string / bytes / stream / blob) into bytes. */
async function toBytes(body) {
  if (body == null) return new Uint8Array()
  if (typeof body === "string") return utf8(body)
  if (body instanceof Uint8Array) return body
  if (body instanceof ArrayBuffer) return new Uint8Array(body)
  if (ArrayBuffer.isView(body)) return new Uint8Array(body.buffer, body.byteOffset, body.byteLength)
  if (typeof body?.getReader === "function") {
    const chunks = []
    const reader = body.getReader()
    for (;;) {
      const { done, value } = await reader.read()
      if (done) break
      chunks.push(typed(value))
    }
    const total = chunks.reduce((n, c) => n + c.length, 0)
    const out = new Uint8Array(total)
    let offset = 0
    for (const c of chunks) {
      out.set(c, offset)
      offset += c.length
    }
    return out
  }
  if (typeof body?.arrayBuffer === "function") return new Uint8Array(await body.arrayBuffer())
  return utf8(String(body))
}

/** Is `model` one that needs the signed `maas_type: benefit` header? */
function isBenefitModel(model) {
  const id = String(model ?? "")
  return benefitModelIds.includes(id) || BENEFIT_MODEL_FALLBACK.includes(id)
}

function rememberBenefitIds(ids) {
  for (const id of ids) if (!benefitModelIds.includes(id)) benefitModelIds.push(id)
}

/**
 * Derive the upstream session headers from the account's credential: every
 * process (and device) running the same account shares one session slot, so
 * the 3-session cap is never spent on plugin-internal churn. The ids change
 * only when STS rotates the credential. 32 hex chars each, like randomHex(16).
 */
async function sessionIdsFor(cred) {
  const digest = await sha256Hex(utf8(`codearts:${cred.access_key_id}`))
  return { chatId: digest.slice(0, 32), sessionId: digest.slice(32, 64) }
}

/** Wait `ms` (±25% jitter so concurrent callers do not sync up). */
function sleepWithJitter(ms) {
  return new Promise((r) => setTimeout(r, Math.round(ms * (0.75 + Math.random() * 0.5))))
}

const initAborted = (signal) => Boolean(signal?.aborted)
const abortError = () => new DOMException("The operation was aborted.", "AbortError")

/** Wait `ms`, or reject as soon as `signal` aborts. */
function delay(ms, signal) {
  return new Promise((resolve, reject) => {
    if (signal?.aborted) return reject(abortError())
    const onAbort = () => {
      clearTimeout(timer)
      reject(abortError())
    }
    const timer = setTimeout(() => {
      signal?.removeEventListener?.("abort", onAbort)
      resolve()
    }, ms)
    signal?.addEventListener?.("abort", onAbort, { once: true })
  })
}

/**
 * The streaming-slot ledger every loader of this plugin process shares.
 *
 * The gateway allows 3 concurrent streaming sessions per ACCOUNT and holds a
 * finished one for ~60 s; a non-streaming request takes no slot at all. Each
 * slot is keyed by the account credential, so every conversation on one
 * account draws on the same 3 slots instead of opening a 4th streaming
 * session that the gateway refuses with TM.00001041.
 *
 * The ledger lives in a file next to the plugin's other state, because the
 * gateway is not the only process that streams: `magpie provider test`, the
 * TUI and every freshly spawned plugin host each run the plugin themselves,
 * and a ledger private to one process would hand each of them its own 3 slots.
 */
const SLOT_STATE_FILE = process.env.MAGPIE_CODEARTS_SLOT_FILE
  ?? path.join(process.env.HOME ?? os.homedir(), ".config", "magpie", "codearts-slots.json")

function readSlotFile() {
  try {
    const raw = JSON.parse(fs.readFileSync(SLOT_STATE_FILE, "utf8"))
    return raw && typeof raw === "object" ? raw : {}
  } catch {
    return {}
  }
}

function writeSlotFile(state) {
  try {
    fs.mkdirSync(path.dirname(SLOT_STATE_FILE), { recursive: true })
    const tmp = `${SLOT_STATE_FILE}.${process.pid}.tmp`
    fs.writeFileSync(tmp, JSON.stringify(state))
    fs.renameSync(tmp, SLOT_STATE_FILE)
  } catch {
    /* the ledger is best effort: a read-only HOME must not break chat */
  }
}

const slots = new Map() // account key → [{ releasedAt }]

/**
 * Book a slot for a streaming request, waiting at most `waitMs`.
 * Returns the slot, or null when the wait budget ran out (the caller then
 * falls back to a non-streaming call, which needs no slot).
 */
async function takeSlot(key, signal, { holdMs = SESSION_HOLD_MS, waitMs = SESSION_WAIT_MS } = {}) {
  const deadline = Date.now() + waitMs
  for (;;) {
    const now = Date.now()
    // Merge the process-local view with what other processes booked.
    const mine = (slots.get(key) ?? []).filter((s) => s.releasedAt > now)
    const stored = Array.isArray(readSlotFile()[key]) ? readSlotFile()[key] : []
    const seen = new Set(mine.map((s) => `${s.releasedAt}`))
    const held = [...mine, ...stored.filter((s) => s.releasedAt > now && !seen.has(`${s.releasedAt}`))]
    slots.set(key, held)
    if (held.length < SESSION_SLOTS) {
      const slot = { releasedAt: now + holdMs }
      held.push(slot)
      const state = readSlotFile()
      state[key] = held
      writeSlotFile(state)
      return slot
    }
    const soonest = held.reduce((a, b) => (a.releasedAt <= b.releasedAt ? a : b))
    const wait = Math.max(0, soonest.releasedAt - now) + SESSION_SLOT_MARGIN_MS
    if (initAborted(signal)) throw abortError()
    // Wait for the soonest release unless that is beyond the budget.
    if (now + (soonest.releasedAt - now) > deadline) return null
    await delay(wait, signal)
  }
}

/** Give a slot back once its request finished; the gateway still holds it. */
function releaseSlot(slot, key) {
  if (!slot) return
  slot.releasedAt = Math.min(slot.releasedAt, Date.now() + SESSION_HOLD_MS)
  if (!key) return
  const now = Date.now()
  const state = readSlotFile()
  const mine = slots.get(key) ?? []
  const merged = [...mine, ...(Array.isArray(state[key]) ? state[key] : [])]
  const seen = new Set()
  state[key] = merged
    .filter((s) => s.releasedAt > now)
    .filter((s) => {
      const k = `${s.releasedAt}`
      if (seen.has(k)) return false
      seen.add(k)
      return true
    })
  writeSlotFile(state)
}

/**
 * A 2xx whose body is really an error frame (the gateway reports an exhausted
 * credit balance that way, inside SSE when streaming). Return it as an HTTP
 * error carrying the upstream message, or null when the body is a real reply.
 */
function quotaErrorOf(res, text) {
  if (!text.includes(QUOTA_ERROR)) return null
  const first = text.split("\n").map((l) => l.replace(/^data:\s*/, "")).find((l) => l.includes(QUOTA_ERROR))
  const parsed = safeJson(first ?? "")
  const msg = firstOf(parsed?.error_msg, "insufficient quota")
  const headers = new Headers(res.headers)
  headers.delete("content-type")
  headers.set("content-type", "application/json; charset=utf-8")
  return new Response(
    JSON.stringify({ error: { message: `CodeArts: 积分不足 (${QUOTA_ERROR}), ${msg}`, type: "insufficient_quota", code: QUOTA_ERROR } }),
    { status: 402, statusText: "Payment Required", headers },
  )
}

/** Copy a response with `text` as its body, dropping stale length/encoding headers. */
function textResponse(res, text) {
  const headers = new Headers(res.headers)
  for (const h of ["content-length", "content-encoding", "transfer-encoding"]) headers.delete(h)
  return new Response(text, { status: res.status, statusText: res.statusText, headers })
}

/**
 * Re-shape a plain chat.completion into a one-shot SSE body, so a caller that
 * asked for `stream: true` but had to be served by a non-streaming call still
 * parses it (one `chat.completion.chunk` with the whole answer, then [DONE]).
 */
async function asSseChunks(res) {
  const text = await res.text()
  const json = safeJson(text)
  const headers = new Headers(res.headers)
  for (const h of ["content-length", "content-encoding", "transfer-encoding"]) headers.delete(h)
  headers.set("content-type", "text/event-stream; charset=utf-8")
  headers.set("cache-control", "no-cache")
  if (!json?.choices) return new Response(text, { status: res.status, statusText: res.statusText, headers })
  const chunk = {
    id: json.id,
    object: "chat.completion.chunk",
    created: json.created ?? Math.floor(Date.now() / 1000),
    model: json.model,
    choices: json.choices.map((c, i) => ({
      index: c.index ?? i,
      // The reply only. Reasoning stays where it belongs (`reasoning_content`),
      // never in content — the caller shows content as the answer.
      delta: { role: "assistant", content: c.message?.content ?? "" },
      finish_reason: c.finish_reason ?? "stop",
    })),
    ...(json.usage ? { usage: json.usage } : {}),
  }
  const body = `data: ${JSON.stringify(chunk)}\n\ndata: [DONE]\n\n`
  return new Response(body, { status: res.status, statusText: res.statusText, headers })
}

/**
 * The plugin's per-request fetch: sign the outgoing chat request with the
 * account's temporary credentials, then send it.
 *
 * A streaming request first takes one of the account's 3 streaming slots (the
 * gateway holds a finished streaming session ~60 s; a non-streaming request
 * needs none). A TM.00001041 that still leaks through — another client on the
 * same account holds the slots — is retried with backoff, and every retry is
 * re-signed so `x-sdk-date` stays current. `context.retryDelays` overrides the
 * backoff schedule and `context.slotHoldMs` the slot hold (tests).
 */
async function signedFetch(cred, input, init, context) {
  const req = typeof Request !== "undefined" && input instanceof Request ? input : null
  const url = req ? req.url : String(input)
  const method = String(init?.method ?? req?.method ?? "GET").toUpperCase()
  const baseHeaders = new Headers(init?.headers ?? req?.headers)
  let rawBody
  if (init?.body != null) rawBody = await toBytes(init.body)
  else if (req) rawBody = new Uint8Array(await req.clone().arrayBuffer())
  else rawBody = new Uint8Array()
  const raw = typeof init?.body === "string" ? safeJson(init.body) : null
  // The host hands the request down with the provider prefix on the model id
  // (`codearts/deepseek-v4.1-flash`), which the gateway does not know: it
  // answers InferHub.002002009.404 "model is not registered" (in an SSE frame
  // when streaming, so it looks like a successful reply). Strip it.
  let body = rawBody
  if (raw && typeof raw.model === "string" && raw.model.startsWith(`${PROVIDER}/`)) {
    raw.model = raw.model.slice(PROVIDER.length + 1)
    body = utf8(JSON.stringify(raw))
  }
  // Ask for the answer, not the thinking — chat only, so introspection and
  // non-chat bodies keep whatever shape they had.
  if (raw && Array.isArray(raw.messages)) {
    if (raw.thinking === undefined) raw.thinking = ENABLE_THINKING
    body = utf8(JSON.stringify(raw))
  }
  // Keep the output budget inside what the gateway accepts, whatever default
  // the caller picked.
  if (raw) {
    let clamped = false
    for (const k of ["max_completion_tokens", "max_tokens"]) {
      if (typeof raw[k] === "number" && raw[k] > MAX_OUTPUT_TOKENS) {
        raw[k] = MAX_OUTPUT_TOKENS
        clamped = true
      }
    }
    if (clamped) body = utf8(JSON.stringify(raw))
  }
  const model = raw?.model
  const streaming = raw?.stream === true
  const extra = isBenefitModel(model) ? { maas_type: "benefit" } : undefined
  // A streaming request that cannot get a slot in time is sent as a plain
  // (non-streaming) call instead: same answer, no slot, no wait.
  let asStream = streaming

  const send = async () => {
    // Only the downgraded path rewrites the body; everything else sends it as built.
    const payload = streaming && !asStream ? utf8(JSON.stringify({ ...raw, stream: false })) : body
    const signed = await signRequestHuawei(
      cred.access_key_id, cred.secret_access_key, cred.security_token,
      method, url, payload, extra,
    )
    const headers = new Headers(baseHeaders)
    signed.forEach((value, key) => {
      if (key !== "host") headers.set(key, value)
    })
    headers.set("Chat-Id", context.chatId)
    headers.set("Session-Id", context.sessionId)
    headers.set("lang", "en")
    return context.fetcher(url, {
      ...init,
      method,
      headers,
      ...(payload.length > 0 ? { body: payload } : {}),
    })
  }

  const delays = context.retryDelays ?? SESSION_RETRY_DELAYS_MS
  const slotKey = context.slotKey ?? cred.access_key_id
  let slot = null
  if (streaming) {
    slot = await takeSlot(slotKey, init?.signal, {
      holdMs: context.slotHoldMs,
      waitMs: context.slotWaitMs,
    })
    // No slot in the budget: plain call, then hand it back as SSE.
    if (!slot) {
      if (init?.signal?.aborted) throw abortError()
      asStream = false
    }
  }
  let res
  try {
    res = await send()
    for (let attempt = 0; res.status === 400 && attempt < delays.length; attempt++) {
      if (init?.signal?.aborted) throw abortError()
      const text = await res.text()
      if (!text.includes(SESSION_LIMIT_ERROR)) {
        // An expired security token (APIG.0602) is the same story as a 401:
        // the credential in this process went stale. Mark it expired so the
        // loader's self-heal refreshes and retries.
        const rebuilt = textResponse(res, text)
        if (text.includes(STALE_TOKEN_ERROR)) {
          const h = new Headers(rebuilt.headers)
          h.set("X-Magpie-Sign-In", "expired")
          return new Response(text, { status: rebuilt.status, statusText: rebuilt.statusText, headers: h })
        }
        return rebuilt
      }
      await sleepWithJitter(delays[attempt])
      res = await send()
    }
  } catch (e) {
    releaseSlot(slot, slotKey)
    throw e
  }
  // A 401/403 is the sign-in gone; magpie marks the account from here.
  if (res.status === 401 || res.status === 403) {
    releaseSlot(slot, slotKey)
    const h = new Headers(res.headers)
    h.set("X-Magpie-Sign-In", "expired")
    return new Response(res.body, { status: res.status, statusText: res.statusText, headers: h })
  }
  // Downgraded call: wrap the whole answer in one chat.completion.chunk so a
  // streaming caller still reads a well-formed SSE body.
  if (streaming && !asStream && res.ok) {
    releaseSlot(slot, slotKey)
    const body = await res.clone().text()
    const quota = quotaErrorOf(res, body)
    if (quota) return quota
    return asSseChunks(new Response(body, { status: res.status, statusText: res.statusText, headers: res.headers }))
  }
  // The slot stays booked until the upstream ends the reply: the gateway keeps
  // counting the session until then, so a body nobody drains would hold it too.
  if (!slot || !res.body) {
    releaseSlot(slot, slotKey)
    return res
  }
  const reader = res.body.getReader()
  // The gateway can answer 200 with an error frame (exhausted credits) instead
  // of a reply. Read ahead far enough to see the first frame, then decide.
  const decoder = new TextDecoder()
  const head = []
  let headText = ""
  while (headText.length < 2048 && !headText.includes("\n\n")) {
    const { done, value } = await reader.read()
    if (done) break
    head.push(value)
    headText += decoder.decode(value, { stream: true })
  }
  const quota = quotaErrorOf(res, headText)
  if (quota) {
    releaseSlot(slot, slotKey)
    return quota
  }
  let replayed = false
  const stream = new ReadableStream({
    async pull(controller) {
      try {
        if (!replayed) {
          replayed = true
          // Anything enqueued keeps the stream alive; the loop guard in pull()
          // only needs the buffered bytes replayed once.
          for (const chunk of head) controller.enqueue(chunk)
          if (head.length === 0) controller.enqueue(new Uint8Array())
          return
        }
        const { done, value } = await reader.read()
        if (done) {
          releaseSlot(slot, slotKey)
          controller.close()
          return
        }
        controller.enqueue(value)
      } catch (e) {
        releaseSlot(slot, slotKey)
        controller.error(e)
      }
    },
    cancel(reason) {
      releaseSlot(slot, slotKey)
      return reader.cancel(reason).catch(() => {})
    },
  })
  return new Response(stream, { status: res.status, statusText: res.statusText, headers: res.headers })
}

/** A signed GET returning the response text, or undefined on any failure. */
async function signedGet(url, cred, fetcher, extraUnsignedHeaders) {
  const signed = await signRequestHuawei(
    cred.access_key_id, cred.secret_access_key, cred.security_token,
    "GET", url, new Uint8Array(),
  )
  const headers = new Headers()
  signed.forEach((value, key) => {
    if (key !== "host") headers.set(key, value)
  })
  if (extraUnsignedHeaders !== undefined) {
    for (const [k, v] of Object.entries(extraUnsignedHeaders)) headers.set(k, v)
  }
  try {
    const res = await fetcher(url, { method: "GET", headers, signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS) })
    if (!res.ok) return undefined
    return await res.text()
  } catch {
    return undefined
  }
}

// ---- model list & account info ---------------------------------------------

function parseModelInfo(m, seen) {
  const rawId = m?.model_id
  if (typeof rawId !== "string" || !rawId) return undefined
  const id = normalizeModelId(rawId)
  // Hide vision models: small context, no tool calls — not agent main models.
  if (id.includes("-VL-") || id.endsWith("-VL")) return undefined
  if (seen.has(id)) return undefined
  seen.add(id)
  const rawName = m.model_name
  const name = typeof rawName === "string" && rawName ? normalizeModelId(rawName) : prettify(id)
  return { id, name, context: CONTEXT_WINDOWS[id] }
}

function extractArray(text, path) {
  const root = safeJson(text)
  if (!root) return undefined
  let value = root
  for (const key of path) {
    if (typeof value !== "object" || value === null) return undefined
    value = value[key]
  }
  return Array.isArray(value) ? value : undefined
}

/**
 * Fetch the account's live model list from the two signed endpoints and merge
 * them, also recording which gateway ids need the benefit header.
 */
async function fetchRemoteModels(cred, fetcher) {
  const models = []
  const seen = new Set()
  const benefitIds = []

  const gatewayText = await signedGet(OPENGW_GATEWAY_CONFIG_URL, cred, fetcher)
  if (gatewayText !== undefined) {
    const arr = extractArray(gatewayText, ["result", "models"])
    for (const item of arr ?? []) {
      if (typeof item !== "object" || item === null) continue
      const mi = parseModelInfo(item, seen)
      if (!mi) continue
      // Only undated gateway ids are the benefit ids we actually send.
      if (item.model_id === mi.id) benefitIds.push(mi.id)
      models.push(mi)
    }
  }

  const snapText = await signedGet(SNAP_MODEL_BUILTIN_URL, cred, fetcher, {
    "Content-Type": "application/json",
    "Agent-Type": "PromptCenter",
    "X-Language": "zh-cn",
  })
  if (snapText !== undefined) {
    const arr = extractArray(snapText, ["builtinModels"])
    for (const item of arr ?? []) {
      if (typeof item !== "object" || item === null) continue
      const mi = parseModelInfo(item, seen)
      if (mi) models.push(mi)
    }
  }

  if (benefitIds.length > 0) rememberBenefitIds(benefitIds)
  return models
}

/** Chinese labels for the credit metric buckets CodeArts reports. */
const CREDIT_METRIC_LABELS = {
  usageTotalPackageCredit: "总积分",
  usageBasicPackageCredit: "基础积分包",
  usageOnDemandPackageCredit: "按需积分包",
  usageBonusPackageCredit: "赠送积分包",
}
const TOTAL_CREDIT_METRIC = "usageTotalPackageCredit"

/** Compact credit counts for the display string (12345 → "1.2万"). */
function formatCredit(n) {
  const v = Math.max(0, Number.isFinite(n) ? n : 0)
  if (v >= 1e8) return `${(v / 1e8).toFixed(1)}亿`
  if (v >= 1e4) return `${(v / 1e4).toFixed(1)}万`
  return String(Math.round(v))
}

/** Map the account's `statistics/plugin` answer to magpie's usage shape. */
function usageFromStatistics(raw) {
  let data = raw
  if (raw && typeof raw.code === "number") {
    if (raw.code !== 0) return { error: firstOf(raw.message, raw.msg, `CodeArts code ${raw.code}`), windows: [] }
    data = asRecord(raw.data)
  }
  if (!data || typeof data !== "object") return { error: "CodeArts could not be parsed", windows: [] }
  const pkg = asRecord(data.package)
  const plan = firstOf(pkg.package_name_cn, pkg.package_name_en, pkg.spec_code)
  const metrics = Array.isArray(data.metrics) ? data.metrics : []

  const windows = []
  for (const item of metrics) {
    const rec = asRecord(item)
    const name = CREDIT_METRIC_LABELS[rec.name]
    if (!name) continue
    const limit = num(rec.package_credit_amount)
    const remain = num(rec.package_credit_remain)
    if (limit <= 0 && remain <= 0) continue // empty bucket, nothing to show
    const amount = clamp(limit > 0 ? ((limit - remain) / limit) * 100 : 0)
    const used = Math.max(0, limit - remain)
    windows.push({
      name,
      used: amount,
      display: `${formatCredit(used)} / ${formatCredit(limit)}`,
      amount: used,
      limit,
      unit: "credits",
    })
  }

  // Keep the package total on top, then the per-bucket breakdown.
  const totalLabel = CREDIT_METRIC_LABELS[TOTAL_CREDIT_METRIC]
  windows.sort((a, b) => (a.name === totalLabel ? -1 : b.name === totalLabel ? 1 : 0))

  if (windows.length > 0) return { plan: plan || undefined, signIn: "kept", windows }
  return { plan: plan || undefined, windows, error: "该账号无积分额度" }
}

// ---- the plugin -------------------------------------------------------------

export const CodeArtsAuthPlugin = async ({ client } = {}, options = {}) => {
  const fetcher = typeof options?.fetch === "function" ? options.fetch : fetch

  const configModel = (m) => ({
    name: m.name ?? m.id,
    limit: { context: m.context ?? 0, output: MAX_OUTPUT_TOKENS },
    tool_call: true,
  })

  const modelOf = (provider, live) => {
    const base = provider.models?.[live.id] ?? {}
    return {
      ...base,
      id: live.id,
      name: live.name || base.name || live.id,
      limit: { context: live.context ?? base.limit?.context ?? 0, output: MAX_OUTPUT_TOKENS },
    }
  }

  return {
    // The provider and the models it has before anyone is signed in.
    config: async (config) => {
      config.provider ??= {}
      config.provider[PROVIDER] ??= {}
      const p = config.provider[PROVIDER]
      p.name ??= "CodeArts"
      p.npm ??= NPM
      p.api ??= CHAT_API_BASE
      p.models = { ...Object.fromEntries(CATALOG.map((m) => [m.id, configModel(m)])), ...(p.models ?? {}) }
    },

    // The account's own list when signed in and CodeArts answers.
    provider: {
      id: PROVIDER,
      async models(provider, { auth } = {}) {
        const cred = credentialOf(auth)
        if (!cred?.access_key_id) return provider.models
        try {
          const list = await fetchRemoteModels(cred, fetcher)
          if (!list.length) return provider.models
          return Object.fromEntries(list.map((m) => [m.id, modelOf(provider, m)]))
        } catch {
          return provider.models
        }
      },
    },

    auth: {
      provider: PROVIDER,
      refreshLead: REFRESH_LEAD_MS,
      maxConcurrency: 4,

      // magpie's own hook: renew the temporary credentials before they expire.
      async refresh(auth) {
        const cred = credentialOf(auth)
        if (!cred) return undefined
        const next = await refreshCredential(cred, fetcher)
        return {
          access: JSON.stringify(next),
          refresh: next.refresh_token,
          expires: expiresFromCredential(next),
        }
      },

      // Every request the account makes is signed here.
      async loader(getAuth) {
        const auth = await getAuth()
        let cred = credentialOf(auth)
        if (!cred?.access_key_id || !cred?.secret_access_key) return {}

        // Single-flight credential refresh, shared by the pre-expiry path and
        // the 401 self-heal below. Failed attempts cool down so a dead
        // refresh_token cannot turn every request into an STS loop.
        let refreshing = null
        let refreshFailedAt = 0
        const REFRESH_RETRY_COOLDOWN_MS = 10_000
        const refreshNow = () => {
          if (!cred.refresh_token) return Promise.resolve(null)
          if (!refreshing) {
            refreshing = refreshCredential(cred, fetcher)
              .then((next) => {
                cred = next
                void persistCredential(client, next)
                return next
              })
              .catch(() => {
                refreshFailedAt = Date.now()
                return null
              })
              .finally(() => { refreshing = null })
          }
          return refreshing
        }

        // Kept for hosts that ignore `auth.refresh` (OpenCode / old magpie):
        // refresh in-band when the credential is about to expire.
        const current = async () => {
          if (!cred.refresh_token || Date.parse(cred.expires_at || 0) - Date.now() > REFRESH_LEAD_MS) return cred
          return (await refreshNow()) ?? cred
        }

        // One session per ACCOUNT, not per request or per process: the gateway
        // keys a session by `Chat-Id` and caps an account at 3 concurrent
        // ones, so per-request ids piled up dead sessions until every chat was
        // rejected (TM.00001041). The ids are derived from the credential, so
        // every process and every device running the same account share a
        // single upstream session (concurrent requests on one session are
        // fine); they only change when the STS credential rotates.
        const context = { fetcher }
        const idsFor = (c) => sessionIdsFor(c)
        return {
          baseURL: CHAT_API_BASE,
          async fetch(input, init = {}) {
            const c = await current()
            const ctx = { ...context, ...(await idsFor(c)) }
            let res = await signedFetch(c, input, init, ctx)
            // A 401 here means the gateway rejected the signature — with IAM
            // that is what an expired/rotated temporary credential looks like.
            // Force one refresh and retry before reporting the response, so a
            // missed scheduled refresh does not brick the account.
            // A 401, or a 400 flagged X-Magpie-Sign-In: expired (APIG.0602
            // security token gone), means this process held a stale
            // credential: refresh once and retry before reporting it.
            const stale = res.status === 401 || new Headers(res.headers).get("X-Magpie-Sign-In") === "expired"
            if (stale && Date.now() - refreshFailedAt > REFRESH_RETRY_COOLDOWN_MS) {
              const next = await refreshNow()
              if (next) res = await signedFetch(next, input, init, { ...ctx, ...(await idsFor(next)) })
            }
            return res
          },
        }
      },

      // magpie's own hook: how much of the plan is left.
      async usage(getAuth) {
        const auth = await getAuth()
        const cred = credentialOf(auth)
        if (!cred?.access_key_id) return { error: "not signed in", windows: [] }
        try {
          const text = await signedGet(SNAP_STATISTICS_URL, cred, fetcher, {
            "Agent-Type": "PromptCenter",
            "X-Language": "zh-cn",
          })
          if (text === undefined) return { error: "CodeArts answered an error", windows: [] }
          return usageFromStatistics(safeJson(text))
        } catch (e) {
          return { error: e?.message ?? String(e), windows: [] }
        }
      },

      methods: [
        {
          type: "oauth",
          label: "Sign in with Huawei Cloud",
          async authorize() {
            const flow = await startOAuthFlow(fetcher)
            return {
              url: flow.loginUrl,
              instructions: "Sign in to Huawei Cloud in the browser; this window closes itself when done.",
              method: "auto",
              async callback() {
                try {
                  const outcome = await flow.result
                  const cred = safeJson(outcome.access)
                  if (!cred?.access_key_id) return { type: "failed", error: "CodeArts did not return a credential" }
                  const accountId = accountIdentityOf(cred) || firstOf(cred.user_name, cred.user_id)
                  return {
                    type: "success",
                    access: outcome.access,
                    refresh: cred.refresh_token,
                    expires: outcome.expires,
                    ...(accountId ? { accountId } : {}),
                  }
                } catch (e) {
                  return { type: "failed", error: e?.message ?? String(e) }
                } finally {
                  await flow.close()
                }
              },
            }
          },
        },
      ],
    },
  }
}

/** Best-effort: store a freshly refreshed credential back on the account. */
async function persistCredential(client, cred) {
  try {
    await client?.auth?.set?.({
      path: { id: PROVIDER },
      body: {
        type: "oauth",
        access: JSON.stringify(cred),
        refresh: cred.refresh_token,
        expires: expiresFromCredential(cred),
      },
    })
  } catch {
    /* best effort */
  }
}

// for tests (never a plugin: magpie only calls exported functions)
export const _internal = {
  PROVIDER, NPM, CATALOG, CONTEXT_WINDOWS, BENEFIT_MODEL_FALLBACK,
  CHAT_API_BASE, SNAP_MODEL_BUILTIN_URL, SNAP_STATISTICS_URL, OPENGW_GATEWAY_CONFIG_URL,
  PORTAL_AUTHORIZE_BASE, STS_TOKEN_ENDPOINT, CLIENT_ID, REDIRECT_PATH,
  firstOf, asRecord, safeJson, num, clamp, prettify, normalizeModelId, formatCredit,
  b64url, utf8, sha256Hex, hmacSha256Hex,
  generatePkcePair, generateDpopKeyPair, keyPairFromStoredJwk, signDpopJws,
  buildCanonicalRequest, signRequestHuawei,
  credentialFromTokenResponse, credentialOf, expiresFromCredential,
  requestToken, exchangeAuthorizationCode, exchangeRefreshToken, refreshCredential,
  buildOAuthLoginUrl, buildPortalLoginResultUrl, parseLegacyCredential, pollForCredential, accountIdentityOf,
  startOAuthCallbackServer, listenOnCallbackPort, startOAuthFlow,
  toBytes, isBenefitModel, rememberBenefitIds, signedFetch, signedGet,
  sessionIdsFor, parseModelInfo, extractArray, fetchRemoteModels, usageFromStatistics,
  SESSION_LIMIT_ERROR, SESSION_RETRY_DELAYS_MS, MAX_OUTPUT_TOKENS, QUOTA_ERROR, quotaErrorOf,
}
