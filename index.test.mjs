// Unit tests for the CodeArts OAuth plugin. Run with: node --test
//
// These tests exercise the pieces magpie calls (_internal helpers) and the
// hooks the plugin returns, with the network stubbed out via `options.fetch`.

import test from "node:test"
import assert from "node:assert/strict"
import { mkdtempSync } from "node:fs"
import { tmpdir } from "node:os"
import { join } from "node:path"

// The streaming-slot ledger is a file so every process shares it; keep the
// tests off the real one.
process.env.MAGPIE_CODEARTS_SLOT_FILE = join(mkdtempSync(join(tmpdir(), "codearts-slots-")), "slots.json")

import { CodeArtsAuthPlugin, _internal as x } from "./index.mjs"

const buf = (s) => new TextEncoder().encode(s)

// ---- crypto primitives -----------------------------------------------------

test("sha256Hex matches the known SHA-256 of the empty string", async () => {
  assert.equal(
    await x.sha256Hex(new Uint8Array()),
    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
  )
})

test("hmacSha256Hex matches RFC 4231 test case 2", async () => {
  assert.equal(
    await x.hmacSha256Hex(buf("Jefe"), buf("what do ya want for nothing?")),
    "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843",
  )
})

test("generatePkcePair derives the S256 challenge from the verifier", async () => {
  const pkce = await x.generatePkcePair()
  assert.match(pkce.codeVerifier, /^[A-Za-z0-9_-]{64}$/)
  const expected = x.b64url(new Uint8Array(await crypto.subtle.digest("SHA-256", buf(pkce.codeVerifier))))
  assert.equal(pkce.codeChallenge, expected)
})

test("signDpopJws produces a verifiable ES256 dpop+jwt", async () => {
  const keyPair = await x.generateDpopKeyPair()
  const jws = await x.signDpopJws(keyPair, "POST", "https://sts.example.com/tokens")
  const [h, p, s] = jws.split(".")
  assert.equal(jws.split(".").length, 3)

  const header = JSON.parse(Buffer.from(h, "base64url").toString())
  assert.equal(header.alg, "ES256")
  assert.equal(header.typ, "dpop+jwt")
  assert.deepEqual(header.jwk, keyPair.publicKeyJwk)

  const payload = JSON.parse(Buffer.from(p, "base64url").toString())
  assert.equal(payload.htm, "POST")
  assert.equal(payload.htu, "https://sts.example.com/tokens")
  assert.equal(typeof payload.iat, "number")
  assert.equal(typeof payload.jti, "string")

  const key = await crypto.subtle.importKey(
    "jwk", keyPair.publicKeyJwk, { name: "ECDSA", namedCurve: "P-256" }, false, ["verify"],
  )
  const ok = await crypto.subtle.verify(
    { name: "ECDSA", hash: "SHA-256" }, key, Buffer.from(s, "base64url"), buf(`${h}.${p}`),
  )
  assert.ok(ok, "the DPoP signature must verify against the advertised public key")
})

// ---- SDK-HMAC-SHA256 signing -----------------------------------------------

test("buildCanonicalRequest lays out the canonical request exactly", () => {
  const headers = new Map([
    ["host", "example.com"],
    ["x-sdk-content-sha256", "H"],
    ["x-sdk-date", "D"],
    ["x-security-token", "ST"],
  ])
  const expected = [
    "GET",
    "/path/",
    "",
    "host:example.com",
    "x-sdk-content-sha256:H",
    "x-sdk-date:D",
    "x-security-token:ST",
    "",
    "host;x-sdk-content-sha256;x-sdk-date;x-security-token",
    "H",
  ].join("\n")
  assert.equal(x.buildCanonicalRequest("GET", "/path/", "", headers, "H"), expected)
})

test("signRequestHuawei signs a GET with the expected header set", async () => {
  const signed = await x.signRequestHuawei(
    "AK", "SK", "ST", "GET", "https://example.com/path", new Uint8Array(), undefined, "20260101T000000Z",
  )
  assert.equal(signed.get("x-sdk-date"), "20260101T000000Z")
  assert.equal(
    signed.get("x-sdk-content-sha256"),
    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
  )
  assert.equal(signed.get("x-security-token"), "ST")
  // GET carries no content-type.
  assert.equal(signed.has("content-type"), false)
  assert.match(
    signed.get("Authorization"),
    /^SDK-HMAC-SHA256 Access=AK,SignedHeaders=host;x-sdk-content-sha256;x-sdk-date;x-security-token,Signature=[0-9a-f]{64}$/,
  )
})

test("signRequestHuawei includes content-type and maas_type in a signed POST", async () => {
  const signed = await x.signRequestHuawei(
    "AK", "SK", "ST", "POST", "https://example.com/api/v2/chat/completions",
    buf('{"model":"glm-5.3-flash"}'), { maas_type: "benefit" }, "20260101T000000Z",
  )
  const auth = signed.get("Authorization")
  assert.match(auth, /SignedHeaders=content-type;host;maas_type;x-sdk-content-sha256;x-sdk-date;x-security-token,/)
  assert.equal(signed.get("content-type"), "application/json")
  assert.equal(signed.get("maas_type"), "benefit")
})

test("signRequestHuawei is deterministic for a fixed date stamp", async () => {
  const args = ["AK", "SK", "ST", "POST", "https://example.com/x", buf("body"), undefined, "20260101T000000Z"]
  const a = await x.signRequestHuawei(...args)
  const b = await x.signRequestHuawei(...args)
  assert.equal(a.get("Authorization"), b.get("Authorization"))
})

// ---- helpers ---------------------------------------------------------------

test("normalizeModelId strips only a trailing 4-digit date", () => {
  assert.equal(x.normalizeModelId("deepseek-v4-flash-0731"), "deepseek-v4-flash")
  assert.equal(x.normalizeModelId("glm-5.3-flash"), "glm-5.3-flash")
  assert.equal(x.normalizeModelId("GLM-5.2"), "GLM-5.2")
})

test("parseModelInfo drops vision models, dedupes, and fills context", () => {
  const seen = new Set()
  assert.equal(x.parseModelInfo({ model_id: "Qwen3-VL-235B", model_name: "Qwen3-VL-235B" }, seen), undefined)
  const a = x.parseModelInfo({ model_id: "GLM-5.2", model_name: "GLM-5.2" }, seen)
  assert.deepEqual(a, { id: "GLM-5.2", name: "GLM-5.2", context: 202752 })
  assert.equal(x.parseModelInfo({ model_id: "GLM-5.2", model_name: "GLM-5.2" }, seen), undefined)
})

test("credentialOf round-trips a credential stored in the access field", async () => {
  const keyPair = await x.generateDpopKeyPair()
  const cred = x.credentialFromTokenResponse(
    { credentials: { access_key_id: "AK", secret_access_key: "SK", security_token: "ST", expiration: "2030-01-01T00:00:00Z" }, refresh_token: "R" },
    "verifier",
    keyPair,
  )
  const auth = { type: "oauth", access: JSON.stringify(cred), refresh: "R" }
  const back = x.credentialOf(auth)
  assert.equal(back.access_key_id, "AK")
  assert.equal(back.refresh_token, "R")
  assert.equal(back.code_verifier, "verifier")
  assert.deepEqual(back.dpop_private_key_jwk, keyPair.privateKeyJwk)
  assert.equal(x.credentialOf({ type: "api", key: "k" }), null)
})

test("expiresFromCredential parses the STS expiration or falls back to +1d", () => {
  assert.equal(x.expiresFromCredential({ expires_at: "2030-01-01T00:00:00Z" }), Date.parse("2030-01-01T00:00:00Z"))
  const soon = x.expiresFromCredential({})
  assert.ok(soon > Date.now() + 86_000_000 && soon <= Date.now() + 86_400_000)
})

test("buildOAuthLoginUrl matches the real IDE parameters", () => {
  const url = new URL(x.buildOAuthLoginUrl(12345, { codeChallenge: "CH" }, "TICKET"))
  assert.equal(url.origin + url.pathname, "https://codearts.huaweicloud.com/portal/authorize")
  const q = url.searchParams
  assert.equal(q.get("client_id"), "codearts-agent")
  assert.equal(q.get("uri_scheme"), "codearts-agent")
  assert.equal(q.get("port"), "12345")
  assert.equal(q.get("code_challenge"), "CH")
  assert.equal(q.get("code_challenge_method"), "SHA-256")
  assert.equal(q.get("ticket_id"), "TICKET")
  assert.equal(q.get("plugin-name"), "snap_AIIDE")
  // The real plugin never sends auth_callback_url (portal derives it from port).
  assert.equal(q.has("auth_callback_url"), false)
})

test("usageFromStatistics maps credit metrics to windows with real numbers", () => {
  const usage = x.usageFromStatistics({
    package: { package_name_cn: "企业版" },
    metrics: [
      { name: "usageTotalPackageCredit", package_credit_amount: 1000, package_credit_remain: 250, package_credit_used: 750 },
      { name: "usageBasicPackageCredit", package_credit_amount: 1000, package_credit_remain: 250, package_credit_used: 750 },
      { name: "usageOnDemandPackageCredit", package_credit_amount: 20000, package_credit_remain: 20000 },
    ],
  })
  assert.equal(usage.plan, "企业版")
  assert.equal(usage.signIn, "kept")
  // The package total is listed first, then the buckets, all with display numbers.
  assert.deepEqual(usage.windows, [
    { name: "总积分", used: 75, display: "750 / 1000", amount: 750, limit: 1000, unit: "credits" },
    { name: "基础积分包", used: 75, display: "750 / 1000", amount: 750, limit: 1000, unit: "credits" },
    { name: "按需积分包", used: 0, display: "0 / 2.0万", amount: 0, limit: 20000, unit: "credits" },
  ])
})

test("usageFromStatistics reports no credit plan when every bucket is empty", () => {
  const usage = x.usageFromStatistics({
    metrics: [{ name: "usageTotalPackageCredit", package_credit_amount: 0, package_credit_remain: 0 }],
  })
  assert.deepEqual(usage.windows, [])
  assert.equal(usage.error, "该账号无积分额度")
})

test("usageFromStatistics surfaces a business error code", () => {
  const usage = x.usageFromStatistics({ code: 500, message: "boom" })
  assert.equal(usage.error, "boom")
})

test("toBytes normalizes strings and views", async () => {
  assert.deepEqual(await x.toBytes("hi"), buf("hi"))
  assert.deepEqual(await x.toBytes(buf("hi")), buf("hi"))
  assert.equal((await x.toBytes(null)).length, 0)
})

test("isBenefitModel honours the static fallback", () => {
  assert.equal(x.isBenefitModel("glm-5.3-flash"), true)
  assert.equal(x.isBenefitModel("GLM-5.2"), false)
})

// ---- remote model list -----------------------------------------------------

const gatewayBody = JSON.stringify({
  result: {
    models: [
      { model_id: "glm-5.3-flash", model_name: "glm-5.3-flash" },
      { model_id: "deepseek-v4-flash-0731", model_name: "deepseek-v4-flash-0731" },
      { model_id: "Qwen3-VL-235B", model_name: "Qwen3-VL-235B" },
    ],
  },
})
const builtinBody = JSON.stringify({ builtinModels: [{ model_id: "GLM-5.2", model_name: "GLM-5.2" }] })

function modelsFetcher(seen) {
  return async (url, init) => {
    seen.push({ url: String(url), auth: new Headers(init?.headers).get("authorization") })
    const body = String(url).includes("opengw") ? gatewayBody : builtinBody
    return new Response(body, { status: 200 })
  }
}

test("fetchRemoteModels merges both endpoints, filters VL, and normalizes ids", async () => {
  const seen = []
  const models = await x.fetchRemoteModels(
    { access_key_id: "AK", secret_access_key: "SK", security_token: "ST" },
    modelsFetcher(seen),
  )
  const ids = models.map((m) => m.id)
  assert.deepEqual(ids, ["glm-5.3-flash", "deepseek-v4-flash", "GLM-5.2"])
  assert.ok(seen.every((s) => String(s.auth).startsWith("SDK-HMAC-SHA256")))
})

test("signedGet returns undefined on a non-2xx response", async () => {
  const fetcher = async () => new Response("nope", { status: 401 })
  const text = await x.signedGet("https://example.com/x", { access_key_id: "AK", secret_access_key: "SK", security_token: "ST" }, fetcher)
  assert.equal(text, undefined)
})

// ---- plugin hooks ----------------------------------------------------------

function makeAuth(cred) {
  return { type: "oauth", access: JSON.stringify(cred), refresh: cred.refresh_token, expires: x.expiresFromCredential(cred) }
}

async function makeCred() {
  const keyPair = await x.generateDpopKeyPair()
  return x.credentialFromTokenResponse(
    { credentials: { access_key_id: "AK", secret_access_key: "SK", security_token: "ST", expiration: "2030-01-01T00:00:00Z" }, refresh_token: "R" },
    "verifier",
    keyPair,
  )
}

test("plugin exposes config, provider.models, and an oauth auth method", async () => {
  const plugin = await CodeArtsAuthPlugin({ client: {} }, {})
  assert.equal(typeof plugin.config, "function")
  assert.equal(plugin.provider.id, "codearts")
  assert.equal(plugin.auth.provider, "codearts")
  assert.equal(plugin.auth.methods.length, 1)
  assert.equal(plugin.auth.methods[0].type, "oauth")

  const config = {}
  await plugin.config(config)
  const p = config.provider.codearts
  assert.equal(p.npm, "@ai-sdk/openai-compatible")
  assert.equal(p.api, x.CHAT_API_BASE)
  assert.ok(p.models["GLM-5.2"])
})

test("loader signs each chat request with SDK-HMAC-SHA256", async () => {
  const cred = await makeCred()
  const seen = []
  const fetcher = async (url, init) => {
    seen.push({ url: String(url), init })
    return new Response("ok", { status: 200 })
  }
  const plugin = await CodeArtsAuthPlugin({ client: {} }, { fetch: fetcher })
  const loaded = await plugin.auth.loader(async () => makeAuth(cred))
  assert.equal(loaded.baseURL, x.CHAT_API_BASE)

  await loaded.fetch("https://snap-access.cn-north-4.myhuaweicloud.com/api/v2/chat/completions", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ model: "GLM-5.2", messages: [] }),
  })

  const headers = new Headers(seen[0].init.headers)
  assert.match(headers.get("authorization"), /^SDK-HMAC-SHA256 Access=AK,/)
  assert.equal(headers.get("lang"), "en")
  assert.ok(headers.get("chat-id"))
  assert.ok(headers.get("session-id"))
  assert.equal(headers.has("maas_type"), false)
  // The signed body must be forwarded verbatim.
  const forwarded = JSON.parse(new TextDecoder().decode(seen[0].init.body))
  assert.deepEqual(forwarded, { model: "GLM-5.2", messages: [], thinking: { type: "enabled" } })
})

test("loader adds a signed maas_type header for benefit models", async () => {
  const cred = await makeCred()
  const seen = []
  const fetcher = async (url, init) => {
    seen.push(init)
    return new Response("ok", { status: 200 })
  }
  const plugin = await CodeArtsAuthPlugin({ client: {} }, { fetch: fetcher })
  const loaded = await plugin.auth.loader(async () => makeAuth(cred))
  await loaded.fetch("https://snap-access.cn-north-4.myhuaweicloud.com/api/v2/chat/completions", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ model: "glm-5.3-flash" }),
  })
  const headers = new Headers(seen[0].headers)
  assert.equal(headers.get("maas_type"), "benefit")
  assert.match(headers.get("authorization"), /SignedHeaders=[^,]*,/)
  assert.ok(headers.get("authorization").split("SignedHeaders=")[1].split(",")[0].includes("maas_type"))
})

test("loader returns nothing when not signed in", async () => {
  const plugin = await CodeArtsAuthPlugin({ client: {} }, {})
  assert.deepEqual(await plugin.auth.loader(async () => ({ type: "api", key: "k" })), {})
})

// ---- session reuse + session-limit retry -----------------------------------

const CHAT_URL = "https://snap-access.cn-north-4.myhuaweicloud.com/api/v2/chat/completions"
const sessionLimitBody = JSON.stringify({
  error_code: x.SESSION_LIMIT_ERROR,
  error_msg: "并发会话数已达上限(3个)，请关闭部分会话后重试。",
})

test("loader reuses one Chat-Id across requests instead of opening a session per call", async () => {
  const cred = await makeCred()
  const seen = []
  const fetcher = async (url, init) => {
    seen.push(new Headers(init.headers).get("chat-id"))
    return new Response("ok", { status: 200 })
  }
  const plugin = await CodeArtsAuthPlugin({ client: {} }, { fetch: fetcher })
  const loaded = await plugin.auth.loader(async () => makeAuth(cred))
  for (let i = 0; i < 3; i++) {
    await loaded.fetch(CHAT_URL, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ model: "GLM-5.2", messages: [] }),
    })
  }
  assert.equal(seen.length, 3)
  assert.ok(seen[0], "every request must carry a Chat-Id")
  assert.equal(seen[0], seen[1])
  assert.equal(seen[0], seen[2])
})

test("session ids are derived from the account, shared across loaders, unique per account", async () => {
  const cred = await makeCred()
  const idsOf = async (c) => await x.sessionIdsFor(c)
  const a1 = await idsOf(cred)
  const a2 = await idsOf(cred)
  // Deterministic: two loaders (processes) on the same account share one session.
  assert.equal(a1.chatId, a2.chatId)
  assert.equal(a1.sessionId, a2.sessionId)
  assert.match(a1.chatId, /^[0-9a-f]{32}$/)
  assert.match(a1.sessionId, /^[0-9a-f]{32}$/)
  // A different account (rotated AK) gets its own session.
  const other = await idsOf({ access_key_id: "AK-other" })
  assert.notEqual(other.chatId, a1.chatId)
  assert.notEqual(other.sessionId, a1.sessionId)
})

test("a fresh loader (new process) sends the same session headers for the same account", async () => {
  const cred = await makeCred()
  const seen = []
  const fetcher = async (url, init) => {
    seen.push({
      chat: new Headers(init.headers).get("chat-id"),
      session: new Headers(init.headers).get("session-id"),
    })
    return new Response("ok", { status: 200 })
  }
  const make = async () => {
    const plugin = await CodeArtsAuthPlugin({ client: {} }, { fetch: fetcher })
    return plugin.auth.loader(async () => makeAuth(cred))
  }
  const init = {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ model: "GLM-5.2", messages: [] }),
  }
  await (await make()).fetch(CHAT_URL, init)
  await (await make()).fetch(CHAT_URL, init)
  assert.equal(seen.length, 2)
  assert.equal(seen[0].chat, seen[1].chat, "two processes on one account must share the session")
  assert.equal(seen[0].session, seen[1].session)
})

test("signedFetch retries the session-limit error with backoff and succeeds", async () => {
  const cred = await makeCred()
  let sends = 0
  const fetcher = async () => {
    sends++
    if (sends <= 2) return new Response(sessionLimitBody, { status: 400 })
    return new Response("ok", { status: 200 })
  }
  const res = await x.signedFetch(cred, CHAT_URL, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ model: "GLM-5.2" }),
  }, { chatId: "chat-1", sessionId: "sess-1", fetcher, retryDelays: [1, 1] })
  assert.equal(res.status, 200)
  assert.equal(sends, 3)
})

test("signedFetch gives up after the backoff budget and returns the 400", async () => {
  const cred = await makeCred()
  let sends = 0
  const fetcher = async () => {
    sends++
    return new Response(sessionLimitBody, { status: 400 })
  }
  const res = await x.signedFetch(cred, CHAT_URL, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ model: "GLM-5.2" }),
  }, { chatId: "chat-1", sessionId: "sess-1", fetcher, retryDelays: [1, 1] })
  assert.equal(res.status, 400)
  assert.equal(sends, 3) // the original send + one per injected delay
  assert.ok((await res.text()).includes(x.SESSION_LIMIT_ERROR))
})

test("signedFetch does not retry session-limit-unrelated 400 errors", async () => {
  const cred = await makeCred()
  let sends = 0
  const fetcher = async () => {
    sends++
    return new Response(JSON.stringify({ error_code: "TM.00009999", error_msg: "其他错误" }), { status: 400 })
  }
  const res = await x.signedFetch(cred, CHAT_URL, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ model: "GLM-5.2" }),
  }, { chatId: "chat-1", sessionId: "sess-1", fetcher, retryDelays: [1, 1] })
  assert.equal(res.status, 400)
  assert.equal(sends, 1)
  assert.ok((await res.text()).includes("TM.00009999"))
})

test("signedFetch aborts between session-limit retries", async () => {
  const cred = await makeCred()
  const controller = new AbortController()
  const fetcher = async () => new Response(sessionLimitBody, { status: 400 })
  const attempt = x.signedFetch(cred, CHAT_URL, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ model: "GLM-5.2" }),
    signal: controller.signal,
  }, { chatId: "chat-1", sessionId: "sess-1", fetcher, retryDelays: [50] })
  controller.abort()
  await assert.rejects(attempt, { name: "AbortError" })
})

test("the provider prefix is stripped from the model id before signing", async () => {
  const cred = await makeCred()
  let sent = ""
  const fetcher = async (url, init) => {
    sent = new TextDecoder().decode(init.body ?? new Uint8Array())
    return new Response('{"ok":true}', { status: 200 })
  }
  const plugin = await CodeArtsAuthPlugin({ client: {} }, { fetch: fetcher })
  const loaded = await plugin.auth.loader(async () => makeAuth(cred))
  await loaded.fetch(CHAT_URL, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ model: "codearts/deepseek-v4.1-flash", messages: [], stream: true }),
  })
  const parsed = JSON.parse(sent)
  assert.equal(parsed.model, "deepseek-v4.1-flash")
  assert.equal(parsed.stream, true)
})

test("accountIdentityOf reads the signer out of the refresh token profile", () => {
  const b64 = (o) => Buffer.from(JSON.stringify(o)).toString("base64url")
  const profile = b64({ account_id: "A1", account_name: "acme", principal_urn: "iam::A1:user:alice" })
  const jwt = `${b64({ alg: "RS256" })}.${b64({ user_profile: profile })}.sig`
  assert.equal(x.accountIdentityOf({ refresh_token: jwt }), "iam::A1:user:alice")
  // Falls back to the account name when the URN is absent.
  const bare = `${b64({ alg: "RS256" })}.${b64({ user_profile: b64({ account_name: "acme" }) })}.sig`
  assert.equal(x.accountIdentityOf({ refresh_token: bare }), "acme")
  // Anything unusable must not invent an identity.
  assert.equal(x.accountIdentityOf({}), "")
  assert.equal(x.accountIdentityOf({ refresh_token: "not-a-jwt" }), "")
  assert.equal(x.accountIdentityOf({ refresh_token: "a.b.c" }), "")
})

test("the output budget is clamped to what the gateway accepts", async () => {
  const cred = await makeCred()
  const sent = []
  const fetcher = async (url, init) => {
    sent.push(JSON.parse(new TextDecoder().decode(init.body ?? new Uint8Array())))
    return new Response('{"ok":true}', { status: 200 })
  }
  const plugin = await CodeArtsAuthPlugin({ client: {} }, { fetch: fetcher })
  const loaded = await plugin.auth.loader(async () => makeAuth(cred))
  await loaded.fetch(CHAT_URL, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ model: "codearts/deepseek-v4.1-flash", messages: [], max_completion_tokens: 128000 }),
  })
  assert.equal(sent[0].max_completion_tokens, x.MAX_OUTPUT_TOKENS)
  // A budget inside the range is left alone.
  await loaded.fetch(CHAT_URL, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ model: "codearts/deepseek-v4.1-flash", messages: [], max_completion_tokens: 1024 }),
  })
  assert.equal(sent[1].max_completion_tokens, 1024)
})

test("model limits declare a usable output budget", async () => {
  const plugin = await CodeArtsAuthPlugin({ client: {} }, {})
  const config = {}
  await plugin.config(config)
  const m = config.provider.codearts.models["GLM-5.2"]
  assert.equal(m.limit.output, x.MAX_OUTPUT_TOKENS)
})

test("chat requests ask for thinking explicitly so it stays out of content", async () => {
  const cred = await makeCred()
  const sent = []
  const fetcher = async (url, init) => {
    sent.push(JSON.parse(new TextDecoder().decode(init.body ?? new Uint8Array())))
    return new Response('{"ok":true}', { status: 200 })
  }
  const plugin = await CodeArtsAuthPlugin({ client: {} }, { fetch: fetcher })
  const loaded = await plugin.auth.loader(async () => makeAuth(cred))
  await loaded.fetch(CHAT_URL, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ model: "codearts/deepseek-v4.1-flash", messages: [{ role: "user", content: "hi" }] }),
  })
  // Left to its default the gateway streams the reasoning as content; asking
  // for it explicitly routes it to reasoning_content instead.
  assert.deepEqual(sent[0].thinking, { type: "enabled" })

  // A caller's own choice wins.
  await loaded.fetch(CHAT_URL, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ model: "codearts/deepseek-v4.1-flash", messages: [], thinking: { type: "disabled" } }),
  })
  assert.deepEqual(sent[1].thinking, { type: "disabled" })
})
test("streaming requests wait for a free slot instead of hitting the 3-session cap", async () => {
  // The gateway allows 3 concurrent streaming sessions per account and holds a
  // finished one ~60 s; a 4th is refused with TM.00001041. Four streaming calls
  // must therefore arrive spaced out, while a non-streaming call never waits.
  const cred = await makeCred()
  const arrivals = []
  const fetcher = async (url, init) => {
    const sent = typeof init.body === "string" ? init.body : new TextDecoder().decode(init.body ?? new Uint8Array())
    arrivals.push({ at: Date.now(), stream: JSON.parse(sent || "{}").stream === true })
    return new Response("data: {}\n\n", { status: 200, headers: { "content-type": "text/event-stream" } })
  }
  const ctx = { chatId: "c", sessionId: "s", fetcher, retryDelays: [], slotHoldMs: 120 }
  const body = (stream, key) => JSON.stringify({ model: "deepseek-v4.1-flash", stream, messages: [{ role: "user", content: key }] })
  const slots = [
    x.signedFetch(cred, CHAT_URL, { method: "POST", body: body(true, "a") }, { ...ctx, slotKey: "acct-1" }),
    x.signedFetch(cred, CHAT_URL, { method: "POST", body: body(true, "b") }, { ...ctx, slotKey: "acct-1" }),
    x.signedFetch(cred, CHAT_URL, { method: "POST", body: body(true, "c") }, { ...ctx, slotKey: "acct-1" }),
  ]
  for (const r of await Promise.all([...slots])) await r.text()
  // The first three went out together; the ledger is now full.
  assert.equal(arrivals.length, 3)
  const started = Date.now()
  const fourth = await x.signedFetch(cred, CHAT_URL, { method: "POST", body: body(true, "d") }, { ...ctx, slotKey: "acct-1" })
  await fourth.text()
  assert.ok(Date.now() - started >= 100, "the 4th streaming request must wait for a slot")
  assert.equal(arrivals.length, 4)

  // A non-streaming request never takes a slot and never waits.
  const t = Date.now()
  const plain = await x.signedFetch(cred, CHAT_URL, { method: "POST", body: body(false, "e") }, { ...ctx, slotKey: "acct-1" })
  await plain.text()
  assert.ok(Date.now() - t < 100, "non-streaming requests must not queue")
})

test("a streaming slot is freed when the body is fully read", async () => {
  const cred = await makeCred()
  let calls = 0
  const fetcher = async () => {
    calls++
    return new Response("data: {}\n\n", { status: 200, headers: { "content-type": "text/event-stream" } })
  }
  // A hold of 5 s would make the second call wait if the slot were not released.
  const ctx = { chatId: "c", sessionId: "s", fetcher, retryDelays: [], slotHoldMs: 5_000, slotKey: "acct-2" }
  const body = JSON.stringify({ model: "deepseek-v4.1-flash", stream: true })
  for (let i = 0; i < 4; i++) {
    const res = await x.signedFetch(cred, CHAT_URL, { method: "POST", body }, ctx)
    assert.equal(await res.text(), "data: {}\n\n")
  }
  assert.equal(calls, 4)
  // Reset the ledger so other tests are unaffected.
  await new Promise((r) => setTimeout(r, 10))
})

test("a streaming request with no slot in budget degrades to a one-shot SSE answer", async () => {
  const cred = await makeCred()
  const bodies = []
  const fetcher = async (url, init) => {
    const sent = typeof init.body === "string" ? init.body : new TextDecoder().decode(init.body ?? new Uint8Array())
    bodies.push(JSON.parse(sent))
    return new Response(JSON.stringify({
      id: "chatcmpl-x", object: "chat.completion", model: "deepseek-v4.1-flash",
      choices: [{ index: 0, message: { role: "assistant", content: "hello" }, finish_reason: "stop" }],
    }), { status: 200, headers: { "content-type": "application/json" } })
  }
  const ctx = { chatId: "c", sessionId: "s", fetcher, retryDelays: [], slotHoldMs: 60_000, slotWaitMs: 30, slotKey: "acct-degrade" }
  const body = JSON.stringify({ model: "deepseek-v4.1-flash", stream: true })
  // Fill all three slots.
  for (let i = 0; i < 3; i++) await (await x.signedFetch(cred, CHAT_URL, { method: "POST", body }, ctx)).text()
  // The next streaming call cannot get a slot: it goes out non-streaming and
  // comes back as SSE with the whole answer in one chunk.
  const res = await x.signedFetch(cred, CHAT_URL, { method: "POST", body }, ctx)
  assert.equal(res.status, 200)
  assert.match(new Headers(res.headers).get("content-type"), /text\/event-stream/)
  const sse = await res.text()
  assert.match(sse, /data: \{.*"object":"chat.completion.chunk".*\}\n\n/)
  assert.ok(sse.trimEnd().endsWith("data: [DONE]"))
  assert.equal(bodies.at(-1).stream, false, "the degraded call must not ask for a stream")
})

test("an aborted wait for a slot rejects", async () => {
  const cred = await makeCred()
  const fetcher = async () => new Response("data: {}\n\n", { status: 200 })
  const ctx = { chatId: "c", sessionId: "s", fetcher, retryDelays: [], slotHoldMs: 60_000, slotWaitMs: 60_000, slotKey: "acct-abort" }
  const body = JSON.stringify({ model: "deepseek-v4.1-flash", stream: true })
  for (let i = 0; i < 3; i++) await (await x.signedFetch(cred, CHAT_URL, { method: "POST", body }, ctx)).text()
  const controller = new AbortController()
  const attempt = x.signedFetch(cred, CHAT_URL, { method: "POST", body, signal: controller.signal }, ctx)
  setTimeout(() => controller.abort(), 20)
  await assert.rejects(attempt, { name: "AbortError" })
})

test("loader refreshes and retries when the security token has expired (APIG.0602)", async () => {
  const cred = await makeCred()
  let chats = 0
  let stsCalls = 0
  const authz = []
  const fetcher = async (url, init) => {
    if (String(url).includes("/chat/completions")) {
      chats++
      authz.push(new Headers(init.headers).get("authorization"))
      if (chats === 1) {
        return new Response(JSON.stringify({
          error_msg: "Bad request: the security token has expired", error_code: "APIG.0602",
        }), { status: 400 })
      }
      return new Response("ok", { status: 200 })
    }
    stsCalls++
    return stsResponse()
  }
  const plugin = await CodeArtsAuthPlugin({ client: {} }, { fetch: fetcher })
  const loaded = await plugin.auth.loader(async () => makeAuth(cred))
  const res = await loaded.fetch(CHAT_URL, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ model: "GLM-5.2", messages: [] }),
  })
  assert.equal(res.status, 200)
  assert.equal(chats, 2, "the stale-token call must be retried once")
  assert.equal(stsCalls, 1)
  assert.match(authz[1], /^SDK-HMAC-SHA256 Access=AK2,/)
})

// ---- 401 self-heal ----------------------------------------------------------

function stsResponse() {
  return new Response(JSON.stringify({
    credentials: { access_key_id: "AK2", secret_access_key: "SK2", security_token: "ST2", expiration: "2031-01-01T00:00:00Z" },
    refresh_token: "R2",
  }), { status: 200 })
}

test("loader force-refreshes the credential and retries once on a 401", async () => {
  const cred = await makeCred()
  const authz = []
  let chats = 0
  let stsCalls = 0
  const fetcher = async (url, init) => {
    if (String(url).includes("/chat/completions")) {
      chats++
      authz.push(new Headers(init.headers).get("authorization"))
      if (chats === 1) {
        return new Response(JSON.stringify({
          error_code: "APIG.0301",
          error_msg: "Incorrect IAM authentication information: verify ak sk signature fail",
        }), { status: 401 })
      }
      return new Response("ok", { status: 200 })
    }
    stsCalls++
    return stsResponse()
  }
  const plugin = await CodeArtsAuthPlugin({ client: {} }, { fetch: fetcher })
  const loaded = await plugin.auth.loader(async () => makeAuth(cred))
  const res = await loaded.fetch(CHAT_URL, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ model: "GLM-5.2", messages: [] }),
  })
  assert.equal(res.status, 200)
  assert.equal(chats, 2)
  assert.equal(stsCalls, 1)
  // The retried request is signed with the refreshed credential.
  assert.match(authz[0], /^SDK-HMAC-SHA256 Access=AK,/)
  assert.match(authz[1], /^SDK-HMAC-SHA256 Access=AK2,/)
})

test("concurrent 401s share a single forced refresh", async () => {
  const cred = await makeCred()
  let chats = 0
  let stsCalls = 0
  const fetcher = async (url) => {
    if (String(url).includes("/chat/completions")) {
      chats++
      if (chats <= 2) return new Response('{"error_code":"APIG.0301"}', { status: 401 })
      return new Response("ok", { status: 200 })
    }
    stsCalls++
    return stsResponse()
  }
  const plugin = await CodeArtsAuthPlugin({ client: {} }, { fetch: fetcher })
  const loaded = await plugin.auth.loader(async () => makeAuth(cred))
  const init = {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ model: "GLM-5.2", messages: [] }),
  }
  const [a, b] = await Promise.all([loaded.fetch(CHAT_URL, init), loaded.fetch(CHAT_URL, init)])
  assert.equal(a.status, 200)
  assert.equal(b.status, 200)
  assert.equal(stsCalls, 1)
})

test("loader marks the account expired when a refresh cannot save the 401", async () => {
  const cred = await makeCred()
  const fetcher = async (url) => {
    if (String(url).includes("/chat/completions")) {
      return new Response('{"error_code":"APIG.0301"}', { status: 401 })
    }
    // The refresh token itself is dead.
    return new Response(JSON.stringify({ error: "invalid_grant" }), { status: 400 })
  }
  const plugin = await CodeArtsAuthPlugin({ client: {} }, { fetch: fetcher })
  const loaded = await plugin.auth.loader(async () => makeAuth(cred))
  const res = await loaded.fetch(CHAT_URL, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ model: "GLM-5.2", messages: [] }),
  })
  assert.equal(res.status, 401)
  assert.equal(new Headers(res.headers).get("x-magpie-sign-in"), "expired")
})

test("auth.refresh exchanges the refresh token for fresh credentials", async () => {
  const cred = await makeCred()
  const fetcher = async (url, init) => {
    assert.equal(String(url), x.STS_TOKEN_ENDPOINT)
    assert.equal(init.method, "POST")
    assert.ok(new Headers(init.headers).get("dpop"))
    return new Response(JSON.stringify({
      credentials: { access_key_id: "AK2", secret_access_key: "SK2", security_token: "ST2", expiration: "2031-01-01T00:00:00Z" },
      refresh_token: "R2",
    }), { status: 200 })
  }
  const plugin = await CodeArtsAuthPlugin({ client: {} }, { fetch: fetcher })
  const next = await plugin.auth.refresh(makeAuth(cred))
  const parsed = JSON.parse(next.access)
  assert.equal(parsed.access_key_id, "AK2")
  assert.equal(next.refresh, "R2")
  assert.equal(next.expires, Date.parse("2031-01-01T00:00:00Z"))
})

test("provider.models returns the account's live list", async () => {
  const cred = await makeCred()
  const plugin = await CodeArtsAuthPlugin({ client: {} }, { fetch: modelsFetcher([]) })
  const provider = { models: { "GLM-5.2": { name: "GLM-5.2", limit: { context: 0, output: 0 } } } }
  const models = await plugin.provider.models(provider, { auth: makeAuth(cred) })
  assert.deepEqual(Object.keys(models).sort(), ["GLM-5.2", "deepseek-v4-flash", "glm-5.3-flash"])
  assert.equal(models["GLM-5.2"].limit.context, 202752)
})

test("provider.models falls back to the catalog when unsigned", async () => {
  const plugin = await CodeArtsAuthPlugin({ client: {} }, {})
  const provider = { models: { "GLM-5.2": {} } }
  assert.deepEqual(await plugin.provider.models(provider, {}), provider.models)
})

test("auth.usage reports the plan's credit window", async () => {
  const cred = await makeCred()
  const fetcher = async (url) => {
    assert.ok(String(url).endsWith("/snap-manager/v1/statistics/plugin"))
    return new Response(JSON.stringify({
      package: { package_name_cn: "企业版" },
      metrics: [{ name: "usageTotalPackageCredit", package_credit_amount: 1000, package_credit_remain: 400 }],
    }), { status: 200 })
  }
  const plugin = await CodeArtsAuthPlugin({ client: {} }, { fetch: fetcher })
  const usage = await plugin.auth.usage(async () => makeAuth(cred))
  assert.equal(usage.plan, "企业版")
  assert.deepEqual(usage.windows, [
    { name: "总积分", used: 60, display: "600 / 1000", amount: 600, limit: 1000, unit: "credits" },
  ])
})

test("an exhausted quota reported inside a 200 becomes a real error", async () => {
  const cred = await makeCred()
  const frame = `data:${JSON.stringify({ error_code: x.QUOTA_ERROR, error_msg: "insufficient quota" })}\n\n`
  const fetcher = async () => new Response(frame, { status: 200, headers: { "content-type": "text/event-stream" } })
  const res = await x.signedFetch(cred, CHAT_URL, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ model: "deepseek-v4.1-flash", stream: true }),
  }, { chatId: "c", sessionId: "s", fetcher, retryDelays: [], slotKey: "acct-quota", slotHoldMs: 1000 })
  // A caller must not see "200 with no answer": say what happened.
  assert.equal(res.status, 402)
  const body = JSON.parse(await res.text())
  assert.equal(body.error.code, x.QUOTA_ERROR)
  assert.match(body.error.message, /积分不足/)
})

test("quotaErrorOf leaves a real reply alone", () => {
  const res = new Response('{"choices":[{"message":{"content":"hi"}}]}', { status: 200 })
  assert.equal(x.quotaErrorOf(res, 'data:{"choices":[{"delta":{"content":"hi"}}]}\n\n'), null)
})

// ---- OAuth callback server -------------------------------------------------

test("startOAuthFlow serves a callback server and a valid login URL", async () => {
  const flow = await x.startOAuthFlow(async () => new Response("", { status: 200 }))
  const url = new URL(flow.loginUrl)
  assert.equal(url.origin + url.pathname, "https://codearts.huaweicloud.com/portal/authorize")
  const port = Number(url.searchParams.get("port"))
  assert.ok(port >= 10000, "callback port must be >= 10000")

  // A callback without code/secret is rejected.
  const res = await fetch(`http://127.0.0.1:${port}/oauth/callback`)
  assert.equal(res.status, 400)

  await flow.close()
})
