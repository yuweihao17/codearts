// Unit tests for the CodeArts OAuth plugin. Run with: node --test
//
// These tests exercise the pieces magpie calls (_internal helpers) and the
// hooks the plugin returns, with the network stubbed out via `options.fetch`.

import test from "node:test"
import assert from "node:assert/strict"
import fs from "node:fs"
import os from "node:os"
import path from "node:path"

import { CodeArtsAuthPlugin, _internal as x } from "./index.mjs"

// Never the real ledger in ~/.config/magpie: every plugin made here keeps its
// check-ins in a scratch file of its own.
const ledgerDir = fs.mkdtempSync(path.join(os.tmpdir(), "codearts-ledger-"))
process.env.MAGPIE_CODEARTS_LEDGER = path.join(ledgerDir, "default.json")
test.after(() => fs.rmSync(ledgerDir, { recursive: true, force: true }))

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

test("canonicalQuery sorts and RFC 3986-encodes the query the way the gateway checks it", () => {
  assert.equal(x.canonicalQuery(new URL("https://h/p?offset=0&limit=100")), "limit=100&offset=0")
  assert.equal(x.canonicalQuery(new URL("https://h/p?agent_id=a b&x=(1)*")), "agent_id=a%20b&x=%281%29%2A")
  assert.equal(x.canonicalQuery(new URL("https://h/p")), "")
})

test("vendorDate reads CodeArts' dates; a zone-less one is Beijing time", () => {
  assert.equal(x.vendorDate("2026-11-01"), Date.parse("2026-10-31T16:00:00Z"))
  assert.equal(x.vendorDate("2026-11-01 08:30:00"), Date.parse("2026-11-01T00:30:00Z"))
  assert.equal(x.vendorDate("2026-11-01T00:00:00Z"), Date.parse("2026-11-01T00:00:00Z"))
  assert.equal(x.vendorDate(1793462400), 1793462400000)
  assert.equal(x.vendorDate("1793462400000"), 1793462400000)
  assert.equal(x.vendorDate("soon"), undefined)
  assert.equal(x.vendorDate(""), undefined)
})

test("creditRateOf reads the 消耗系数 from one tier or a list of them", () => {
  assert.equal(x.creditRateOf({ ratio: 2, ratio_display: "1.5" }), 1.5)
  assert.equal(x.creditRateOf([{ ratio_display: 0.3 }, { ratio_display: 2 }]), 0.3)
  assert.equal(x.creditRateOf(undefined), 0)
  assert.equal(x.creditRateOf({ ratio_display: "0" }), 0)
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

test("upstreamModelId drops the host's provider prefix only", () => {
  assert.equal(x.upstreamModelId("codearts/deepseek-v4.1-flash"), "deepseek-v4.1-flash")
  assert.equal(x.upstreamModelId("GLM-5.2"), "GLM-5.2")
  assert.equal(x.upstreamModelId("other/GLM-5.2"), "other/GLM-5.2")
})

test("parseModelInfo drops vision models, dedupes, and fills context", () => {
  const seen = new Set()
  assert.equal(x.parseModelInfo({ model_id: "Qwen3-VL-235B", model_name: "Qwen3-VL-235B" }, seen), undefined)
  assert.equal(x.parseModelInfo({ model_id: "kimi-k2.6-vl" }, seen), undefined)
  const a = x.parseModelInfo({ model_id: "GLM-5.2", model_name: "GLM-5.2" }, seen)
  assert.deepEqual(a, { id: "GLM-5.2", name: "GLM-5.2", context: 202752 })
  assert.equal(x.parseModelInfo({ model_id: "GLM-5.2", model_name: "GLM-5.2" }, seen), undefined)
})

test("parseModelInfo keeps the dated id, and its bare form as another model", () => {
  const seen = new Set()
  const dated = x.parseModelInfo({ model_id: "deepseek-v4-flash-0731", model_name: "deepseek-v4-flash-0731", max_tokens: 131072 }, seen)
  assert.deepEqual(dated, { id: "deepseek-v4-flash-0731", name: "deepseek-v4-flash", context: 1048576, output: x.MAX_OUTPUT_TOKENS })
  assert.equal(x.parseModelInfo({ model_id: "deepseek-v4-flash" }, seen).id, "deepseek-v4-flash")
})

test("prepareChatBody reshapes a chat into what the gateway accepts and meters", () => {
  const out = x.prepareChatBody({ model: "codearts/GLM-5.2", messages: [], max_tokens: 128000 })
  assert.equal(out.fold, true)
  assert.deepEqual(out.body, { model: "GLM-5.2", messages: [], max_tokens: x.MAX_OUTPUT_TOKENS, thinking: { type: "enabled" }, stream: true })

  const streamed = x.prepareChatBody({ model: "GLM-5.2", messages: [], stream: true, thinking: { type: "disabled" } })
  assert.equal(streamed.fold, false)
  assert.deepEqual(streamed.body.thinking, { type: "disabled" })

  assert.equal(x.prepareChatBody({ model: "GLM-5.2", messages: [] }, { thinking: false }).body.thinking, undefined)
  assert.equal(x.prepareChatBody({ model: "GLM-5.2" }), null)
  assert.equal(x.prepareChatBody(null), null)
})

test("classifyHead tells an answer from an embedded error", () => {
  const role = `data: ${JSON.stringify({ choices: [{ delta: { role: "assistant" } }] })}\n\n`
  const content = `data: ${JSON.stringify({ choices: [{ delta: { content: "hi" } }] })}\n\n`
  const cap = `data: {"error_code":"TM.00001041","error_msg":"并发会话数已达上限(3个)"}\n\n`
  assert.equal(x.classifyHead(role, false), undefined) // a role-only delta decides nothing
  assert.equal(x.classifyHead(role + content, false), "answer")
  assert.equal(x.classifyHead(role + cap, false), "TM.00001041")
  assert.equal(x.classifyHead(`data: {"error_code":"TM.00001041"`, false), undefined) // not whole yet
  assert.equal(x.classifyHead("", true), "answer")
  assert.equal(x.classifyHead(JSON.stringify({ choices: [{ message: { content: "x" } }] }), true), "answer")
})

test("errorCodeOf / errorMessageOf / isRateLimitCode read the gateway's errors", () => {
  const text = '{"error_code":"InferHub.4291.200","error_msg":"insufficient \\"quota\\""}'
  assert.equal(x.errorCodeOf(text), "InferHub.4291.200")
  assert.equal(x.errorMessageOf(text), 'insufficient "quota"')
  assert.equal(x.isRateLimitCode("InferHub.4291.200"), true)
  assert.equal(x.isRateLimitCode("81111.429"), true)
  assert.equal(x.isRateLimitCode("InferHub.002002009.404"), false)
  assert.equal(x.isStaleCredential('{"error_code":"APIG.0602"}'), true)
  assert.equal(x.isStaleCredential('{"error_code":"APIG.0301","error_msg":"verify ak sk signature fail"}'), true)
})

test("accountIdentityOf reads the signer from the refresh token's user_profile", () => {
  const b64u = (o) => Buffer.from(JSON.stringify(o)).toString("base64url")
  const profile = { principal_urn: "iam::d1:user:alice", user_name: "alice" }
  const asString = `h.${b64u({ user_profile: JSON.stringify(profile) })}.s`
  assert.deepEqual(x.accountIdentityOf({ refresh_token: asString }), { id: "iam::d1:user:alice", name: "alice" })
  const asB64 = `h.${b64u({ user_profile: b64u(profile) })}.s`
  assert.deepEqual(x.accountIdentityOf({ refresh_token: asB64 }), { id: "iam::d1:user:alice", name: "alice" })
  assert.deepEqual(x.accountIdentityOf({ refresh_token: "opaque", user_name: "bob" }), { id: "bob", name: "bob" })
})

test("accountSessionIds is stable per account and differs between accounts", async () => {
  const a = await x.accountSessionIds({ session_id: "s1", access_key_id: "AK1" })
  assert.deepEqual(await x.accountSessionIds({ session_id: "s1", access_key_id: "AK2" }), a)
  assert.notDeepEqual(await x.accountSessionIds({ session_id: "s2", access_key_id: "AK1" }), a)
  assert.match(a.sessionId, /^[0-9a-f]{32}$/)
  assert.match(a.chatId, /^[0-9a-f]{32}$/)
})

test("createConcurrencyGate caps permits, admits in order, and honours abort", async () => {
  const gate = x.createConcurrencyGate(2)
  const r1 = await gate.acquire()
  const r2 = await gate.acquire()
  let third = false
  const p3 = gate.acquire().then((r) => { third = true; return r })
  const ctl = new AbortController()
  const p4 = gate.acquire(ctl.signal)
  await new Promise((r) => setTimeout(r, 5))
  assert.equal(third, false)
  assert.equal(gate.waiting, 2)
  ctl.abort()
  await assert.rejects(p4, { name: "AbortError" })
  r1()
  r1() // a second release is a no-op
  const r3 = await p3
  assert.equal(gate.active, 2)
  r2()
  r3()
  assert.equal(gate.active, 0)
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
  // The package total is listed first, then the buckets, all with display
  // numbers; only the total may pause the account, the buckets are aside.
  assert.deepEqual(usage.windows, [
    { name: "总积分", used: 75, display: "750 / 1000", amount: 750, limit: 1000, unit: "credits" },
    { name: "基础积分包", used: 75, display: "750 / 1000", amount: 750, limit: 1000, unit: "credits", aside: true },
    { name: "按需积分包", used: 0, display: "0 / 2.0万", amount: 0, limit: 20000, unit: "credits", aside: true },
  ])
})

test("usageFromStatistics adds the free daily pool as an aside window for the free models", () => {
  const usage = x.usageFromStatistics(
    { metrics: [{ name: "usageTotalPackageCredit", package_credit_amount: 1000, package_credit_remain: 1000 }] },
    { result: { daily_token_limit: 10_000_000, daily_tokens_used: 2_500_000 } },
  )
  const free = usage.windows.find((w) => w.name === "免费额度")
  assert.equal(free.used, 25)
  assert.equal(free.display, "250.0万 / 1000.0万")
  assert.equal(free.unit, "tokens")
  assert.equal(free.aside, true)
  assert.ok(free.models.includes("glm-5.3-flash"))
  assert.equal(x.benefitWindow({ result: {} }), undefined)
})

test("usageFromStatistics: the monthly buckets reset at end_date, expiring credits are said", () => {
  const usage = x.usageFromStatistics({
    end_date: "2026-11-01",
    metrics: [
      { name: "usageTotalPackageCredit", package_credit_amount: 6500, package_credit_remain: 6000 },
      { name: "usageBasicPackageCredit", package_credit_amount: 500, package_credit_remain: 0 },
      { name: "usageBonusPackageCredit", package_credit_amount: 6000, package_credit_remain: 6000, package_credit_expiring_amount: 1000 },
    ],
  })
  const [total, basic, bonus] = usage.windows
  const reset = new Date(Date.parse("2026-10-31T16:00:00Z")).toISOString()
  assert.equal(total.resetsAt, reset)
  assert.equal(basic.resetsAt, reset)
  assert.equal(bonus.resetsAt, undefined, "given credits don't come back at the month's end")
  assert.equal(bonus.display, "0 / 6000 · 1000 即将过期")
})

test("usageFromStatistics: the soonest check-in credits to lapse show on the bonus bucket", () => {
  const now = Date.now()
  const day = 86_400_000
  const grants = [
    { at: new Date(now - 40 * day).toISOString(), credit: 1000, expiresAt: new Date(now - 10 * day).toISOString() }, // gone
    { at: new Date(now - 25 * day).toISOString(), credit: 1000, expiresAt: new Date(now + 5 * day).toISOString() },
    { at: new Date(now - 2 * day).toISOString(), credit: 1000, expiresAt: new Date(now + 28 * day).toISOString() },
  ]
  const usage = x.usageFromStatistics({
    metrics: [
      { name: "usageTotalPackageCredit", package_credit_amount: 7000, package_credit_remain: 6500 },
      { name: "usageBonusPackageCredit", package_credit_amount: 2000, package_credit_remain: 1500 },
    ],
  }, undefined, { grants })
  const bonus = usage.windows.find((w) => w.name === "赠送积分包")
  assert.equal(bonus.runsOutAt, grants[1].expiresAt)
  assert.equal(bonus.runsOut, 1000)
  // The total loses them too.
  assert.equal(usage.windows.find((w) => w.name === "总积分").runsOutAt, grants[1].expiresAt)
  assert.equal(x.soonestLapse(x.grantBatches([grants[0]])), undefined)
})

// Shaped as the console's own answers (personal-usage → 获取明细).
const day = 86_400_000
const iso = (ms) => new Date(ms).toISOString()
function creditFetcher(now = Date.now()) {
  const planEnd = now + 31 * day
  const signUp = now + 30 * day
  const checkin = signUp + 52_000 // the same Beijing day, a minute later
  const ok = (data) => new Response(JSON.stringify({ code: 0, message: "ok", data }), { status: 200 })
  const fetcher = async (url, init) => {
    const u = String(url)
    const body = init?.body ? JSON.parse(new TextDecoder().decode(init.body)) : undefined
    if (u === x.PACKAGE_CREDIT_PAGE_URL) {
      const list = body.packageTypes.includes("basic")
        ? [{ packageType: "basic", creditAmount: 500.0, creditUsed: 0.0, validityPeriod: "31", expiredTime: iso(planEnd).replace("Z", "+00:00"), status: 1 }]
        : []
      return new Response(JSON.stringify({ list, total: list.length, pageNum: 1, pageSize: 100 }), { status: 200 })
    }
    if (u === x.OPS_CREDIT_OVERVIEW_URL) {
      return ok({ items: [
        { campaignId: 4, campaignTitle: "新用户注册送 4000 积分", totalClaimed: 4000, totalConsumed: 0, totalExpired: 0 },
        { campaignId: 1, campaignTitle: "每日签到领1000积分", totalClaimed: 1000, totalConsumed: 0, totalExpired: 0 },
        { campaignId: 9, campaignTitle: "用完了", totalClaimed: 1000, totalConsumed: 1000, totalExpired: 0 },
      ] })
    }
    if (u === x.OPS_CREDIT_CAMPAIGN_URL(4)) {
      return ok({ campaignId: 4, benefits: [{ status: "CONFIRMED", claimedAmount: 4000, consumedAmount: 0, expiredAmount: 0, claimedAt: iso(signUp - 30 * day), expireAt: iso(signUp) }] })
    }
    if (u === x.OPS_CREDIT_CAMPAIGN_URL(1)) {
      return ok({ campaignId: 1, expirePolicy: { strategy: "DURATION", duration: 30, durationUnit: "DAYS" }, benefits: [{ status: "CONFIRMED", claimedAmount: 1000, consumedAmount: 0, expiredAmount: 0, claimedAt: iso(checkin - 30 * day), expireAt: iso(checkin) }] })
    }
    throw new Error(`unexpected ${u}`)
  }
  return { fetcher, planEnd, signUp, checkin }
}

test("fetchCreditBatches reads every batch with its own expiry, signed", async () => {
  const { fetcher, planEnd, signUp, checkin } = creditFetcher()
  const seen = []
  const batches = await x.fetchCreditBatches({ access_key_id: "AK", secret_access_key: "SK", security_token: "ST" }, async (url, init) => {
    seen.push([init.method, String(url), new Headers(init.headers).get("authorization")])
    return fetcher(url, init)
  })
  assert.deepEqual(batches, [
    { metric: "usageBasicPackageCredit", amount: 500, left: 500, expiresAt: planEnd },
    { metric: "usageBonusPackageCredit", amount: 4000, left: 4000, expiresAt: signUp },
    { metric: "usageBonusPackageCredit", amount: 1000, left: 1000, expiresAt: checkin },
  ])
  // A spent campaign is not asked for its grants.
  assert.equal(seen.some((s) => s[1] === x.OPS_CREDIT_CAMPAIGN_URL(9)), false)
  assert.ok(seen.every((s) => String(s[2]).startsWith("SDK-HMAC-SHA256 ")))
  // Nothing reached: no batches, so the caller falls back.
  assert.equal(await x.fetchCreditBatches({ access_key_id: "AK", secret_access_key: "SK", security_token: "ST" }, async () => new Response("", { status: 401 })), undefined)
})

test("usage with the vendor's batches: the plan's end is the reset, the grants' the lapse", async () => {
  const cred = await makeCred()
  const { fetcher: credit, planEnd, signUp } = creditFetcher()
  const fetcher = async (url, init) => {
    if (String(url).endsWith("/snap-manager/v1/statistics/plugin")) {
      return new Response(JSON.stringify({
        end_date: "2099-01-01",
        metrics: [
          { name: "usageTotalPackageCredit", package_credit_amount: 5500, package_credit_remain: 5500 },
          { name: "usageBasicPackageCredit", package_credit_amount: 500, package_credit_remain: 500 },
          { name: "usageBonusPackageCredit", package_credit_amount: 5000, package_credit_remain: 5000 },
        ],
      }), { status: 200 })
    }
    if (String(url) === x.BENEFIT_BALANCE_URL) return new Response("", { status: 404 })
    return credit(url, init)
  }
  const plugin = await CodeArtsAuthPlugin({ client: {} }, { fetch: fetcher, ledgerPath: path.join(ledgerDir, "unused.json") })
  const usage = await plugin.auth.usage(async () => makeAuth(cred))
  const [total, basic, bonus] = usage.windows
  // To the second, from the plan's batch, not end_date's day.
  assert.equal(total.resetsAt, iso(planEnd))
  assert.equal(basic.resetsAt, iso(planEnd))
  assert.equal(basic.runsOutAt, undefined, "the plan's credits come back, they don't lapse")
  // The sign-up grant and that day's check-in lapse together.
  assert.equal(bonus.runsOutAt, iso(signUp))
  assert.equal(bonus.runsOut, 5000)
  assert.equal(total.runsOutAt, iso(signUp))
  assert.equal(total.runsOut, 5000)
})

test("the free pool window comes back at the next Beijing midnight", () => {
  const w = x.benefitWindow({ result: { daily_token_limit: 100, daily_tokens_used: 10 } })
  const at = Date.parse(w.resetsAt)
  assert.ok(at > Date.now() && at - Date.now() <= 86_400_000)
  assert.equal(new Date(at + 8 * 3600 * 1000).toISOString().slice(11, 19), "00:00:00")
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

test("isBenefitModel honours the static fallback and the host's prefix", () => {
  assert.equal(x.isBenefitModel("glm-5.3-flash"), true)
  assert.equal(x.isBenefitModel("codearts/glm-5.3-flash"), true)
  assert.equal(x.isBenefitModel("deepseek-v4-flash-0731"), true)
  // The bare id is a different, paid model.
  assert.equal(x.isBenefitModel("deepseek-v4-flash"), false)
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

function modelsFetcher(seen, { claim = "0000", agents, detail } = {}) {
  return async (url, init) => {
    const u = String(url)
    seen.push({ url: u, method: init?.method, auth: new Headers(init?.headers).get("authorization") })
    if (u === x.BENEFIT_CLAIM_URL) return new Response(JSON.stringify({ error_code: claim, error_msg: claim === "0000" ? "ok" : "权益不存在" }), { status: 200 })
    if (u === x.AGENT_LIST_URL) return new Response(JSON.stringify(agents ?? { total: 0, agents: [] }), { status: 200 })
    if (u.startsWith(`${x.AGENT_DETAIL_URL("")}`)) return new Response(JSON.stringify(detail ?? { gpts: { models: [] } }), { status: 200 })
    const body = u.includes("opengw") ? gatewayBody : builtinBody
    return new Response(body, { status: 200 })
  }
}

test("fetchRemoteModels merges both endpoints, filters VL, and keeps the published ids", async () => {
  const seen = []
  const models = await x.fetchRemoteModels(
    { access_key_id: "AK", secret_access_key: "SK", security_token: "ST" },
    modelsFetcher(seen),
  )
  const ids = models.map((m) => m.id)
  assert.deepEqual(ids, ["glm-5.3-flash", "deepseek-v4-flash-0731", "GLM-5.2"])
  // Everything gateway/config publishes is a free model.
  assert.deepEqual(models.map((m) => m.benefit === true), [true, true, false])
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
  assert.equal(typeof plugin.auth.checkin, "function")
  assert.equal(plugin.auth.maxConcurrency, x.ACCOUNT_MAX_INFLIGHT)

  const config = {}
  await plugin.config(config)
  const p = config.provider.codearts
  assert.equal(p.npm, "@ai-sdk/openai-compatible")
  assert.equal(p.api, x.CHAT_API_BASE)
  assert.ok(p.models["GLM-5.2"])
  assert.equal(p.models["GLM-5"], undefined)
  // The output budget is declared; nothing is called free before the
  // account's own list says so.
  assert.equal(p.models["GLM-5.2"].limit.output, x.MAX_OUTPUT_TOKENS)
  assert.equal(p.models["GLM-5.2"].free, undefined)
  assert.equal(p.models["glm-5.3-flash"].free, undefined)
})

const CHAT_URL = "https://snap-access.cn-north-4.myhuaweicloud.com/api/v2/chat/completions"
const sse = (...events) => events.map((e) => `data: ${typeof e === "string" ? e : JSON.stringify(e)}\n\n`).join("")
const sseResponse = (text) => new Response(text, { status: 200, headers: { "content-type": "text/event-stream" } })
const chatInit = (body) => ({ method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(body) })
const okStream = sse(
  { id: "c1", model: "GLM-5.2", choices: [{ index: 0, delta: { role: "assistant" } }] },
  { id: "c1", choices: [{ index: 0, delta: { content: "你好" } }] },
  { id: "c1", choices: [{ index: 0, delta: {}, finish_reason: "stop" }] },
  "[DONE]",
)
const fastRetry = { retryDelays: [1], retryBudgetMs: 2_000 }

test("loader signs each chat request with SDK-HMAC-SHA256 and sends it metered", async () => {
  const cred = await makeCred()
  const seen = []
  const fetcher = async (url, init) => {
    seen.push({ url: String(url), init })
    return sseResponse(okStream)
  }
  const plugin = await CodeArtsAuthPlugin({ client: {} }, { fetch: fetcher })
  const loaded = await plugin.auth.loader(async () => makeAuth(cred))
  assert.equal(loaded.baseURL, x.CHAT_API_BASE)

  const res = await loaded.fetch(CHAT_URL, chatInit({ model: "codearts/GLM-5.2", messages: [] }))

  const headers = new Headers(seen[0].init.headers)
  assert.match(headers.get("authorization"), /^SDK-HMAC-SHA256 Access=AK,/)
  assert.equal(headers.get("lang"), "en")
  assert.match(headers.get("chat-id"), /^[0-9a-f]{32}$/)
  assert.match(headers.get("session-id"), /^[0-9a-f]{32}$/)
  assert.equal(headers.has("maas_type"), false)
  // The body signed and sent: bare model, explicit thinking, streamed.
  assert.deepEqual(JSON.parse(new TextDecoder().decode(seen[0].init.body)), {
    model: "GLM-5.2", messages: [], thinking: { type: "enabled" }, stream: true,
  })
  // The caller asked for JSON, so the stream comes back folded.
  assert.equal(res.headers.get("content-type"), "application/json")
  const json = await res.json()
  assert.equal(json.object, "chat.completion")
  assert.deepEqual(json.choices[0].message, { role: "assistant", content: "你好" })
  assert.equal(json.choices[0].finish_reason, "stop")
})

test("one account keeps one Chat-Id/Session-Id across requests and loaders", async () => {
  const cred = await makeCred()
  const seen = []
  const fetcher = async (url, init) => {
    seen.push(new Headers(init.headers))
    return sseResponse(okStream)
  }
  const plugin = await CodeArtsAuthPlugin({ client: {} }, { fetch: fetcher })
  const a = await plugin.auth.loader(async () => makeAuth(cred))
  const b = await plugin.auth.loader(async () => makeAuth(cred))
  await (await a.fetch(CHAT_URL, chatInit({ model: "GLM-5.2", messages: [] }))).text()
  await (await a.fetch(CHAT_URL, chatInit({ model: "GLM-5.2", messages: [] }))).text()
  await (await b.fetch(CHAT_URL, chatInit({ model: "GLM-5.2", messages: [] }))).text()
  assert.equal(new Set(seen.map((h) => h.get("chat-id"))).size, 1)
  assert.equal(new Set(seen.map((h) => h.get("session-id"))).size, 1)
})

test("a streaming caller gets the upstream stream intact, peeked bytes included", async () => {
  const cred = await makeCred()
  const plugin = await CodeArtsAuthPlugin({ client: {} }, { fetch: async () => sseResponse(okStream) })
  const loaded = await plugin.auth.loader(async () => makeAuth(cred))
  const res = await loaded.fetch(CHAT_URL, chatInit({ model: "GLM-5.2", messages: [], stream: true }))
  assert.equal(res.status, 200)
  assert.equal(await res.text(), okStream)
})

test("a folded answer keeps reasoning, tool calls and usage apart", async () => {
  const cred = await makeCred()
  const stream = sse(
    { id: "c2", model: "deepseek-v4.1-flash", choices: [{ delta: { reasoning_content: "想一想" } }] },
    { id: "c2", choices: [{ delta: { tool_calls: [{ index: 0, id: "call_1", type: "function", function: { name: "read", arguments: '{"pa' } }] } }] },
    { id: "c2", choices: [{ delta: { tool_calls: [{ index: 0, function: { arguments: 'th":"a"}' } }] } }] },
    { id: "c2", choices: [{ delta: {}, finish_reason: "tool_calls" }], usage: { prompt_tokens: 5, completion_tokens: 7, total_tokens: 12 } },
    "[DONE]",
  )
  const plugin = await CodeArtsAuthPlugin({ client: {} }, { fetch: async () => sseResponse(stream) })
  const loaded = await plugin.auth.loader(async () => makeAuth(cred))
  const json = await (await loaded.fetch(CHAT_URL, chatInit({ model: "deepseek-v4.1-flash", messages: [] }))).json()
  const msg = json.choices[0].message
  assert.equal(msg.content, "")
  assert.equal(msg.reasoning_content, "想一想")
  assert.deepEqual(msg.tool_calls, [{ id: "call_1", type: "function", function: { name: "read", arguments: '{"path":"a"}' } }])
  assert.equal(json.choices[0].finish_reason, "tool_calls")
  assert.deepEqual(json.usage, { prompt_tokens: 5, completion_tokens: 7, total_tokens: 12 })
})

const capBody = JSON.stringify({ error_code: "TM.00001041", error_msg: "并发会话数已达上限(3个)，请关闭部分会话后重试。" })

test("TM.00001041 as a 400 is retried, re-signed, until a session frees", async () => {
  const cred = await makeCred()
  let calls = 0
  const fetcher = async () => {
    calls += 1
    return calls <= 2 ? new Response(capBody, { status: 400 }) : sseResponse(okStream)
  }
  const plugin = await CodeArtsAuthPlugin({ client: {} }, { fetch: fetcher, ...fastRetry })
  const loaded = await plugin.auth.loader(async () => makeAuth(cred))
  const res = await loaded.fetch(CHAT_URL, chatInit({ model: "GLM-5.2", messages: [], stream: true }))
  assert.equal(calls, 3)
  assert.equal(res.status, 200)
  assert.equal(await res.text(), okStream)
})

test("TM.00001041 inside a 200 stream is retried too", async () => {
  const cred = await makeCred()
  let calls = 0
  const fetcher = async () => {
    calls += 1
    return calls === 1 ? sseResponse(sse({ choices: [{ delta: { role: "assistant" } }] }, JSON.parse(capBody))) : sseResponse(okStream)
  }
  const plugin = await CodeArtsAuthPlugin({ client: {} }, { fetch: fetcher, ...fastRetry })
  const loaded = await plugin.auth.loader(async () => makeAuth(cred))
  const json = await (await loaded.fetch(CHAT_URL, chatInit({ model: "GLM-5.2", messages: [] }))).json()
  assert.equal(calls, 2)
  assert.equal(json.choices[0].message.content, "你好")
})

test("a session cap that outlasts the budget comes back as a 429 magpie fails over on", async () => {
  const cred = await makeCred()
  let calls = 0
  const fetcher = async () => {
    calls += 1
    return new Response(capBody, { status: 400 })
  }
  const plugin = await CodeArtsAuthPlugin({ client: {} }, { fetch: fetcher, retryDelays: [5], retryBudgetMs: 12 })
  const loaded = await plugin.auth.loader(async () => makeAuth(cred))
  const res = await loaded.fetch(CHAT_URL, chatInit({ model: "GLM-5.2", messages: [] }))
  assert.equal(res.status, 429)
  assert.ok(calls >= 2)
  const body = await res.json()
  assert.equal(body.error.code, "TM.00001041")
  assert.match(body.error.message, /并发会话数已达上限/)
})

test("an abort while waiting for a session stops the retries", async () => {
  const cred = await makeCred()
  const fetcher = async () => new Response(capBody, { status: 400 })
  const plugin = await CodeArtsAuthPlugin({ client: {} }, { fetch: fetcher, retryDelays: [10_000], retryBudgetMs: 60_000 })
  const loaded = await plugin.auth.loader(async () => makeAuth(cred))
  const ctl = new AbortController()
  setTimeout(() => ctl.abort(), 20)
  await assert.rejects(
    loaded.fetch(CHAT_URL, { ...chatInit({ model: "GLM-5.2", messages: [] }), signal: ctl.signal }),
    { name: "AbortError" },
  )
})

test("an error inside a 200 becomes a status magpie acts on, with the vendor's words", async () => {
  const cred = await makeCred()
  const quota = sse({ error_code: "InferHub.4291.200", error_msg: "insufficient quota" })
  const unknown = sse({ error_code: "InferHub.002002009.404", error_msg: "model is not registered" })
  let next = quota
  const plugin = await CodeArtsAuthPlugin({ client: {} }, { fetch: async () => sseResponse(next) })
  const loaded = await plugin.auth.loader(async () => makeAuth(cred))

  const a = await loaded.fetch(CHAT_URL, chatInit({ model: "GLM-5.2", messages: [], stream: true }))
  assert.equal(a.status, 429)
  assert.match((await a.json()).error.message, /insufficient quota \(InferHub\.4291\.200\)/)

  // A model the account doesn't have: retrying can't help, so a 400.
  next = unknown
  const b = await loaded.fetch(CHAT_URL, chatInit({ model: "GLM-5.2", messages: [] }))
  assert.equal(b.status, 400)
  const body = await b.json()
  assert.equal(body.error.code, "InferHub.002002009.404")
  assert.equal(body.error.message.startsWith("CodeArts"), false, "magpie adds the provider name itself")
})

test("embeddedErrorStatus sorts the gateway's codes into what magpie acts on", () => {
  assert.equal(x.embeddedErrorStatus("InferHub.4291.200"), 429)
  assert.equal(x.embeddedErrorStatus("81114.429"), 429)
  assert.equal(x.embeddedErrorStatus("InferHub.4004.200"), 400)
  assert.equal(x.embeddedErrorStatus("ModelArts.81009.404"), 400)
  assert.equal(x.embeddedErrorStatus("InferHub.001001005.400"), 400)
  assert.equal(x.embeddedErrorStatus("InferHub.5000.500"), 502)
})

test("every chat carries the agent's session headers: one session, a fresh trace", async () => {
  const cred = await makeCred()
  const seen = []
  const plugin = await CodeArtsAuthPlugin({ client: {} }, {
    fetch: async (url, init) => {
      seen.push(new Headers(init.headers))
      return sseResponse(okStream)
    },
  })
  const loaded = await plugin.auth.loader(async () => makeAuth(cred))
  await (await loaded.fetch(CHAT_URL, chatInit({ model: "GLM-5.2", messages: [] }))).text()
  await (await loaded.fetch(CHAT_URL, chatInit({ model: "GLM-5.2", messages: [] }))).text()
  const [a, b] = seen
  assert.match(a.get("x-ot-session-id"), /^[0-9a-f]{32}$/)
  assert.equal(a.get("x-ot-session-id"), b.get("x-ot-session-id"))
  assert.equal(a.get("user-session-id"), a.get("x-ot-session-id"))
  assert.notEqual(a.get("x-ot-trace-id"), b.get("x-ot-trace-id"))
  assert.notEqual(a.get("x-snap-traceid"), b.get("x-snap-traceid"))
})

test("only the account's live free list decides the benefit header", async () => {
  const before = [...x.BENEFIT_MODEL_FALLBACK]
  try {
    const fetcher = async (url) => String(url).includes("opengw")
      ? new Response(JSON.stringify({ result: { models: [{ model_id: "glm-5.3-flash" }] } }), { status: 200 })
      : new Response(JSON.stringify({ builtinModels: [{ model_id: "deepseek-v4.1-flash", model_name: "DeepSeek-V4.1-Flash" }] }), { status: 200 })
    const models = await x.fetchRemoteModels({ access_key_id: "AK", secret_access_key: "SK", security_token: "ST" }, fetcher)
    assert.deepEqual(models.map((m) => [m.id, m.benefit === true]), [["glm-5.3-flash", true], ["deepseek-v4.1-flash", false]])
    // In the fallback, but this account lists it as a plain builtin model.
    assert.equal(x.isBenefitModel("deepseek-v4.1-flash"), false)
    assert.equal(x.isBenefitModel("glm-5.3-flash"), true)
    // A failed read keeps what was known.
    await x.fetchRemoteModels({ access_key_id: "AK", secret_access_key: "SK", security_token: "ST" }, async () => new Response("", { status: 500 }))
    assert.equal(x.isBenefitModel("glm-5.3-flash"), true)
  } finally {
    x.rememberBenefitIds(before)
  }
})

test("benefit not found sends the request again as the plain builtin model, and remembers it", async () => {
  const before = [...x.BENEFIT_MODEL_FALLBACK]
  try {
    // The free list and the builtin list both name the model.
    await x.fetchRemoteModels({ access_key_id: "AK", secret_access_key: "SK", security_token: "ST" }, async (url) => String(url).includes("opengw")
      ? new Response(JSON.stringify({ result: { models: [{ model_id: "deepseek-v4.1-flash" }] } }), { status: 200 })
      : new Response(JSON.stringify({ builtinModels: [{ model_id: "deepseek-v4.1-flash" }] }), { status: 200 }))
    const cred = await makeCred()
    const sent = []
    const plugin = await CodeArtsAuthPlugin({ client: {} }, {
      fetch: async (url, init) => {
        const benefit = new Headers(init.headers).get("maas_type")
        sent.push(benefit)
        return benefit
          ? sseResponse(sse({ error_code: "InferHub.4004.200", error_msg: "benefit not found" }))
          : sseResponse(okStream)
      },
    })
    const loaded = await plugin.auth.loader(async () => makeAuth(cred))
    const a = await loaded.fetch(CHAT_URL, chatInit({ model: "codearts/deepseek-v4.1-flash", messages: [] }))
    assert.equal(a.status, 200)
    assert.equal((await a.json()).choices[0].message.content, "你好")
    const b = await loaded.fetch(CHAT_URL, chatInit({ model: "deepseek-v4.1-flash", messages: [] }))
    await b.text()
    assert.deepEqual(sent, ["benefit", null, null])
  } finally {
    x.rememberBenefitIds(before)
  }
})

test("a 429 that queues the request is waited out the agent's way, then sent again", async () => {
  const cred = await makeCred()
  const calls = []
  let polls = 0
  const fetcher = async (url, init) => {
    calls.push([init.method, String(url), new Headers(init.headers).get("authorization")])
    if (String(url) === x.TRACE_QUEUE_URL("T1")) {
      polls += 1
      return new Response(JSON.stringify(polls < 2 ? { status: "queued", queue_length: 2, retry_after: 0 } : { status: "promoted" }), { status: 200 })
    }
    return calls.filter((c) => c[1] === CHAT_URL).length === 1
      ? new Response("{}", { status: 429, headers: { "queue-status": "queued", "trace-id": "T1", "retry-after": "0" } })
      : sseResponse(okStream)
  }
  const plugin = await CodeArtsAuthPlugin({ client: {} }, { fetch: fetcher })
  const loaded = await plugin.auth.loader(async () => makeAuth(cred))
  const res = await loaded.fetch(CHAT_URL, chatInit({ model: "GLM-5.2", messages: [], stream: true }))
  assert.equal(res.status, 200)
  assert.equal(await res.text(), okStream)
  assert.deepEqual(calls.map((c) => [c[0], c[1]]), [
    ["POST", CHAT_URL],
    ["GET", x.TRACE_QUEUE_URL("T1")],
    ["GET", x.TRACE_QUEUE_URL("T1")],
    ["POST", CHAT_URL],
  ])
  assert.ok(calls.every((c) => String(c[2]).startsWith("SDK-HMAC-SHA256 ")))
})

test("giving up in the queue takes the request out of it", async () => {
  const cred = await makeCred()
  const calls = []
  const fetcher = async (url, init) => {
    calls.push([init.method, String(url)])
    if (String(url) === x.TRACE_QUEUE_URL("T2")) return new Response(JSON.stringify({ status: "queued", retry_after: 30 }), { status: 200 })
    return new Response("{}", { status: 429, headers: { "queue-status": "queued", "trace-id": "T2", "retry-after": "30" } })
  }
  const plugin = await CodeArtsAuthPlugin({ client: {} }, { fetch: fetcher })
  const loaded = await plugin.auth.loader(async () => makeAuth(cred))
  const ctl = new AbortController()
  setTimeout(() => ctl.abort(), 20)
  await assert.rejects(loaded.fetch(CHAT_URL, { ...chatInit({ model: "GLM-5.2", messages: [] }), signal: ctl.signal }), { name: "AbortError" })
  await new Promise((r) => setTimeout(r, 10))
  assert.deepEqual(calls.at(-1), ["DELETE", x.TRACE_QUEUE_URL("T2")])

  // A queue the wait budget can't cover is left at once, and answered 429.
  calls.length = 0
  const quick = await CodeArtsAuthPlugin({ client: {} }, { fetch: fetcher, queueBudgetMs: 1_000 })
  const res = await (await quick.auth.loader(async () => makeAuth(cred))).fetch(CHAT_URL, chatInit({ model: "GLM-5.2", messages: [] }))
  assert.equal(res.status, 429)
  await new Promise((r) => setTimeout(r, 10))
  assert.deepEqual(calls.map((c) => c[0]), ["POST", "DELETE"])
})

test("a 429 that is no queue passes through for magpie to fail over", async () => {
  const cred = await makeCred()
  const plugin = await CodeArtsAuthPlugin({ client: {} }, { fetch: async () => new Response('{"error_code":"81111.429"}', { status: 429 }) })
  const loaded = await plugin.auth.loader(async () => makeAuth(cred))
  const res = await loaded.fetch(CHAT_URL, chatInit({ model: "GLM-5.2", messages: [] }))
  assert.equal(res.status, 429)
  assert.equal(await res.text(), '{"error_code":"81111.429"}')
})

test("a model that refuses the injected thinking parameter gets the caller's request", async () => {
  const cred = await makeCred()
  const bodies = []
  const fetcher = async (url, init) => {
    bodies.push(JSON.parse(new TextDecoder().decode(init.body)))
    return bodies.length === 1
      ? new Response('{"error_code":"InferHub.001001005.400","error_msg":"unknown field: thinking"}', { status: 400 })
      : sseResponse(okStream)
  }
  const plugin = await CodeArtsAuthPlugin({ client: {} }, { fetch: fetcher })
  const loaded = await plugin.auth.loader(async () => makeAuth(cred))
  const res = await loaded.fetch(CHAT_URL, chatInit({ model: "openpangu-2.0-pro", messages: [], stream: true }))
  assert.equal(res.status, 200)
  assert.deepEqual(bodies[0].thinking, { type: "enabled" })
  assert.equal("thinking" in bodies[1], false)
})

test("other upstream errors pass through untouched", async () => {
  const cred = await makeCred()
  const body = JSON.stringify({ error_code: "InferHub.001001005.400", error_msg: "RANGE_VALIDATOR" })
  let calls = 0
  const plugin = await CodeArtsAuthPlugin({ client: {} }, {
    fetch: async () => {
      calls += 1
      return new Response(body, { status: 400 })
    },
    ...fastRetry,
  })
  const loaded = await plugin.auth.loader(async () => makeAuth(cred))
  const res = await loaded.fetch(CHAT_URL, chatInit({ model: "GLM-5.2", messages: [] }))
  assert.equal(res.status, 400)
  assert.equal(await res.text(), body)
  assert.equal(calls, 1)
})

const stsBody = (ak, refresh) => JSON.stringify({
  credentials: { access_key_id: ak, secret_access_key: `SK-${ak}`, security_token: `ST-${ak}`, expiration: "2031-01-01T00:00:00Z" },
  refresh_token: refresh,
})

test("a stale credential is renewed once, the request sent again, and the renewal kept", async () => {
  const cred = await makeCred()
  const sets = []
  const chats = []
  const fetcher = async (url, init) => {
    if (String(url) === x.STS_TOKEN_ENDPOINT) return new Response(stsBody("AK2", "R2"), { status: 200 })
    chats.push(new Headers(init.headers).get("authorization"))
    return chats.length === 1
      ? new Response(JSON.stringify({ error_code: "APIG.0602", error_msg: "the security token has expired" }), { status: 400 })
      : sseResponse(okStream)
  }
  const client = { auth: { set: async (o) => { sets.push(o) } } }
  const plugin = await CodeArtsAuthPlugin({ client }, { fetch: fetcher })
  const loaded = await plugin.auth.loader(async () => ({ ...makeAuth(cred), accountId: "alice" }))
  const res = await loaded.fetch(CHAT_URL, chatInit({ model: "GLM-5.2", messages: [], stream: true }))
  assert.equal(res.status, 200)
  assert.match(chats[0], /Access=AK,/)
  assert.match(chats[1], /Access=AK2,/)
  assert.equal(sets.length, 1)
  const saved = sets[0].body
  assert.equal(saved.accountId, "alice") // the host keeps the record whole: nothing may be lost
  assert.equal(saved.refresh, "R2")
  const next = JSON.parse(saved.access)
  assert.equal(next.access_key_id, "AK2")
  assert.equal(next.session_id, cred.session_id)
})

test("a stale credential takes over a renewal already stored instead of refreshing again", async () => {
  const cred = await makeCred()
  const renewed = { ...cred, access_key_id: "AK9", secret_access_key: "SK9", security_token: "ST9" }
  let reads = 0
  const getAuth = async () => (reads++ === 0 ? makeAuth(cred) : makeAuth(renewed))
  const chats = []
  const fetcher = async (url, init) => {
    assert.notEqual(String(url), x.STS_TOKEN_ENDPOINT, "the stored renewal must be used, not a second refresh")
    chats.push(new Headers(init.headers).get("authorization"))
    return chats.length === 1 ? new Response('{"error_code":"APIG.0301"}', { status: 401 }) : sseResponse(okStream)
  }
  const plugin = await CodeArtsAuthPlugin({ client: {} }, { fetch: fetcher })
  const loaded = await plugin.auth.loader(getAuth)
  const res = await loaded.fetch(CHAT_URL, chatInit({ model: "GLM-5.2", messages: [], stream: true }))
  assert.equal(res.status, 200)
  assert.match(chats[1], /Access=AK9,/)
})

test("a spent refresh token marks the sign-in and stops calling the vendor", async () => {
  const cred = await makeCred()
  let chats = 0
  const fetcher = async (url) => {
    if (String(url) === x.STS_TOKEN_ENDPOINT) {
      return new Response(JSON.stringify({ error_code: "STS5.1806", error_msg: "refresh token has been used" }), { status: 400 })
    }
    chats += 1
    return new Response('{"error_code":"APIG.0602","error_msg":"the security token has expired"}', { status: 400 })
  }
  const plugin = await CodeArtsAuthPlugin({ client: {} }, { fetch: fetcher })
  const loaded = await plugin.auth.loader(async () => makeAuth(cred))
  const a = await loaded.fetch(CHAT_URL, chatInit({ model: "GLM-5.2", messages: [] }))
  assert.equal(a.status, 401)
  assert.equal(a.headers.get("x-magpie-sign-in"), "expired")
  const b = await loaded.fetch(CHAT_URL, chatInit({ model: "GLM-5.2", messages: [] }))
  assert.equal(b.status, 401)
  assert.equal(chats, 1)
})

test("requestToken reads a spent refresh token as a sign-in gone for good", async () => {
  const keyPair = await x.generateDpopKeyPair()
  const fetcher = async () => new Response(JSON.stringify({ error_code: "STS5.1806", error_msg: "refresh token has been used" }), { status: 400 })
  await assert.rejects(x.requestToken({ grant_type: "refresh_token" }, keyPair, fetcher), (e) => e.signIn === "expired")
  const flaky = async () => new Response(JSON.stringify({ error_code: "STS.0001", error_msg: "dpop proof rejected" }), { status: 400 })
  await assert.rejects(x.requestToken({ grant_type: "refresh_token" }, keyPair, flaky), (e) => e.signIn === undefined)
})

test("in-flight chats per account are capped, and a permit comes back when the body ends", async () => {
  const cred = await makeCred()
  const controllers = []
  const fetcher = async () => {
    let ctl
    const body = new ReadableStream({ start(c) { ctl = c } })
    ctl.enqueue(new TextEncoder().encode(sse({ choices: [{ delta: { content: "x" } }] })))
    controllers.push(ctl)
    return sseResponse(body)
  }
  const plugin = await CodeArtsAuthPlugin({ client: {} }, { fetch: fetcher })
  const loaded = await plugin.auth.loader(async () => makeAuth(cred))
  const send = () => loaded.fetch(CHAT_URL, chatInit({ model: "GLM-5.2", messages: [], stream: true }))
  const first = await Promise.all([send(), send(), send()])
  const fourth = send()
  await new Promise((r) => setTimeout(r, 20))
  assert.equal(controllers.length, 3, "the 4th waits for a permit")
  controllers[0].close()
  await first[0].text()
  const res = await fourth
  assert.equal(controllers.length, 4)
  for (const c of controllers.slice(1)) c.close()
  await Promise.all([...first.slice(1), res].map((r) => r.text()))
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
  assert.deepEqual(Object.keys(models).sort(), ["GLM-5.2", "deepseek-v4-flash-0731", "glm-5.3-flash"])
  assert.equal(models["GLM-5.2"].limit.context, 202752)
  assert.equal(models["GLM-5.2"].limit.output, x.MAX_OUTPUT_TOKENS)
  assert.equal(models["GLM-5.2"].free, false)
  assert.equal(models["deepseek-v4-flash-0731"].free, true)
})

const agentList = { total: 2, agents: [{ agent_id: "a-other", original_id: "DT-Agent" }, { agent_id: "a-code-1", original_id: "CodeAgent" }] }
const agentDetail = {
  gpts: {
    models: [
      { model_name: "GLM-5.2", model_parameters: { model_id: "GLM-5.2", thinking_type: "enabled", context_window: 202752, max_tokens: 131072 }, credit: [{ ratio: 1, ratio_display: "1.50" }] },
      { model_name: "GLM-5.3", model_parameters: { model_id: "glm-5.3", context_window: 1048576 }, credit: { ratio_display: 0.8 } },
      { model_name: "My Own", model_type: "custom", model_parameters: { model_id: "my-own" } },
    ],
  },
}

test("provider.models: free models once claimed, rates and parameters from the CodeAgent", async () => {
  const before = [...x.BENEFIT_MODEL_FALLBACK]
  try {
    const cred = await makeCred()
    const seen = []
    const plugin = await CodeArtsAuthPlugin({ client: {} }, { fetch: modelsFetcher(seen, { agents: agentList, detail: agentDetail }) })
    const provider = { models: {} }
    const models = await plugin.provider.models(provider, { auth: makeAuth(cred) })
    assert.deepEqual(Object.keys(models).sort(), ["GLM-5.2", "deepseek-v4-flash-0731", "glm-5.3", "glm-5.3-flash"])
    // Today's benefit claimed: the gateway's models are free and carry no rate.
    assert.equal(models["glm-5.3-flash"].free, true)
    assert.equal(models["glm-5.3-flash"].rate, undefined)
    // The rest bill credits at the agent's own rate.
    assert.equal(models["GLM-5.2"].free, false)
    assert.equal(models["GLM-5.2"].rate, 1.5)
    assert.equal(models["GLM-5.2"].capabilities.reasoning, true)
    assert.equal(models["GLM-5.2"].limit.output, x.MAX_OUTPUT_TOKENS)
    // Only the agent lists it: one more model; a user's own is left out.
    assert.equal(models["glm-5.3"].rate, 0.8)
    assert.equal(models["glm-5.3"].limit.context, 1048576)
    assert.equal(models["my-own"], undefined)
    // The claim went out signed, and the detail named the CodeAgent's own id.
    const claim = seen.find((s) => s.url === x.BENEFIT_CLAIM_URL)
    assert.equal(claim.method, "POST")
    assert.match(claim.auth, /^SDK-HMAC-SHA256 /)
    assert.ok(seen.some((s) => s.url === x.AGENT_DETAIL_URL("a-code-1")))
    // Listed again the same day: no second claim, no second agent list.
    await plugin.provider.models(provider, { auth: makeAuth(cred) })
    assert.equal(seen.filter((s) => s.url === x.BENEFIT_CLAIM_URL).length, 1)
    assert.equal(seen.filter((s) => s.url === x.AGENT_LIST_URL).length, 1)
  } finally {
    x.rememberBenefitIds(before)
  }
})

test("the model list comes from the main agent: original_id build, then CodeAgent, then the IDE's id", async () => {
  const cred = { access_key_id: "AK", secret_access_key: "SK", security_token: "ST" }
  const detailOf = (models) => new Response(JSON.stringify({ gpts: { models } }), { status: 200 })
  const glm = [{ model_name: "GLM-5.2", model_parameters: { model_id: "GLM-5.2", context_window: 1048576 }, credit: [{ ratio: 0.05, ratio_display: 0.7 }] }]
  const run = async (agents, detail) => {
    const asked = []
    const state = {}
    const models = await x.fetchAgentModels(cred, async (url) => {
      const u = String(url)
      if (u === x.AGENT_LIST_URL) return agents ? new Response(JSON.stringify({ total: agents.length, agents }), { status: 200 }) : new Response("", { status: 500 })
      const id = new URL(u).searchParams.get("agent_id")
      asked.push(id)
      return detailOf(detail(id))
    }, state)
    return { models, asked, state }
  }
  // The account's own agents, as the IDE lists them: the main one is "build".
  const agents = [
    { agent_id: "9f0e5cb64a104dcfb4aa90dbedab7dcf", original_id: "team-leader" },
    { agent_id: "a8bcb36232554267a5142361cc25a393", original_id: "build" },
    { agent_id: "c0de", original_id: "CodeAgent" },
  ]
  let r = await run(agents, (id) => (id === "a8bcb36232554267a5142361cc25a393" ? glm : []))
  assert.deepEqual(r.asked, ["a8bcb36232554267a5142361cc25a393"])
  assert.equal(r.models[0].rate, 0.7)
  assert.equal(r.state.agentId, "a8bcb36232554267a5142361cc25a393")
  // An agent with an empty list: the next one is asked.
  r = await run(agents, (id) => (id === "c0de" ? glm : []))
  assert.deepEqual(r.asked, ["a8bcb36232554267a5142361cc25a393", "c0de"])
  // No agent list at all: the IDE's own id for the main agent.
  r = await run(undefined, (id) => (id === "a8bcb36232554267a5142361cc25a393" ? glm : []))
  assert.deepEqual(r.asked, ["a8bcb36232554267a5142361cc25a393"])
  assert.equal(r.models[0].context, 1048576)
})

test("a benefit the account can't claim: no free models, and no benefit header", async () => {
  const before = [...x.BENEFIT_MODEL_FALLBACK]
  try {
    const cred = await makeCred()
    const seen = []
    const list = modelsFetcher(seen, { claim: "4004" })
    const sent = []
    const fetcher = async (url, init) => {
      if (String(url) === CHAT_URL) {
        sent.push(new Headers(init.headers).get("maas_type"))
        return sseResponse(okStream)
      }
      return list(url, init)
    }
    const plugin = await CodeArtsAuthPlugin({ client: {} }, { fetch: fetcher })
    const models = await plugin.provider.models({ models: {} }, { auth: makeAuth(cred) })
    // The gateway's free-only models can't be called without the benefit.
    assert.deepEqual(Object.keys(models), ["GLM-5.2"])
    const loaded = await plugin.auth.loader(async () => makeAuth(cred))
    await (await loaded.fetch(CHAT_URL, chatInit({ model: "glm-5.3-flash", messages: [] }))).text()
    assert.deepEqual(sent, [null])
  } finally {
    x.rememberBenefitIds(before)
  }
})

test("ensureBenefitClaimed claims once a day and asks again only an hour after a refusal", async () => {
  const cred = await makeCred()
  let claims = 0
  let answer = "4006"
  const fetcher = async () => {
    claims += 1
    return new Response(JSON.stringify({ error_code: answer }), { status: 200 })
  }
  const state = {}
  assert.equal(await x.ensureBenefitClaimed(cred, fetcher, state), false)
  answer = "0000"
  assert.equal(await x.ensureBenefitClaimed(cred, fetcher, state), false) // within the hour
  assert.equal(claims, 1)
  state.claim.at -= 61 * 60 * 1000
  assert.equal(await x.ensureBenefitClaimed(cred, fetcher, state), true)
  assert.equal(await x.ensureBenefitClaimed(cred, fetcher, state), true)
  assert.equal(claims, 2)
  // Unreachable: the last answer stands, nothing is cached over it.
  const down = async () => { throw new Error("offline") }
  assert.equal(await x.ensureBenefitClaimed(cred, down, { claim: { day: "2000-01-01", ok: true, at: 0 } }), true)
})

test("provider.models falls back to the catalog when unsigned", async () => {
  const plugin = await CodeArtsAuthPlugin({ client: {} }, {})
  const provider = { models: { "GLM-5.2": {} } }
  assert.deepEqual(await plugin.provider.models(provider, {}), provider.models)
})

test("auth.usage reports the plan's credit window (the free pool is best-effort)", async () => {
  const cred = await makeCred()
  const asked = []
  const fetcher = async (url) => {
    asked.push(String(url))
    if (String(url) === x.BENEFIT_BALANCE_URL) return new Response("nope", { status: 404 })
    // The batch reads fail here: the usage read goes on without them.
    if (String(url) === x.PACKAGE_CREDIT_PAGE_URL || String(url) === x.OPS_CREDIT_OVERVIEW_URL) return new Response("", { status: 500 })
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
  assert.deepEqual(asked, [x.SNAP_STATISTICS_URL, x.BENEFIT_BALANCE_URL, x.PACKAGE_CREDIT_PAGE_URL, x.PACKAGE_CREDIT_PAGE_URL, x.OPS_CREDIT_OVERVIEW_URL])
  // Read again within ten minutes: the batches aren't.
  await plugin.auth.usage(async () => makeAuth(cred))
  assert.equal(asked.filter((u) => u === x.OPS_CREDIT_OVERVIEW_URL).length, 1)
})

// ---- daily check-in ----------------------------------------------------------

/** A stand-in for the three ops endpoints: `state` is the USER_LOGIN item. */
function opsFetcher(state, { claim, confirm } = {}) {
  const calls = []
  const ok = (data) => new Response(JSON.stringify({ code: 0, message: "ok", data }), { status: 200 })
  const fetcher = async (url, init) => {
    const u = String(url)
    const headers = new Headers(init.headers)
    const body = init.body ? JSON.parse(new TextDecoder().decode(init.body)) : undefined
    calls.push({ url: u, method: init.method, body, headers })
    if (u === x.OPS_DELIVERY_URL) {
      const items = [{ campaignId: 7, type: "INVITE_USER", claimable: false }]
      if (state.item) items.push(state.item)
      return state.listStatus ? new Response('{"error_code":"APIG.0301","error_msg":"verify ak sk signature fail"}', { status: state.listStatus }) : ok({ items })
    }
    if (u === x.OPS_CLAIM_URL) {
      if (claim) return claim(state)
      state.item = { ...state.item, claimable: false, status: "CLAIMED" }
      return ok({ id: 42, benefitAmount: 1000 })
    }
    if (u === x.OPS_CONFIRM_URL) {
      if (confirm) return confirm(state)
      state.item = { ...state.item, status: "CONFIRMED" }
      return ok(null)
    }
    throw new Error(`unexpected ${u}`)
  }
  return { fetcher, calls }
}

const daily = (extra) => ({ campaignId: 1, type: "USER_LOGIN", title: "每日领取", claimable: true, status: "ENTRY", benefitAmount: 1000, ...extra })

test("checkin claims and confirms the daily benefit the way the IDE does", async () => {
  const cred = await makeCred()
  const { fetcher, calls } = opsFetcher({ item: daily() })
  const plugin = await CodeArtsAuthPlugin({ client: {} }, { fetch: fetcher })
  const r = await plugin.auth.checkin(async () => makeAuth(cred))
  assert.deepEqual(r, { outcome: "claimed", credit: 1000, message: "+1000 积分" })
  assert.deepEqual(calls.map((c) => [c.method, c.url]), [
    ["GET", x.OPS_DELIVERY_URL],
    ["POST", x.OPS_CLAIM_URL],
    ["POST", x.OPS_CONFIRM_URL],
  ])
  assert.deepEqual(calls[1].body, { campaignId: 1, channel: "IDE" })
  assert.deepEqual(calls[2].body, { campaignId: 1 })
  for (const c of calls) {
    const auth = c.headers.get("authorization")
    assert.match(auth, /^SDK-HMAC-SHA256 Access=AK,/)
    // Routing headers go along unsigned: signing them breaks the signature.
    assert.equal(c.headers.get("agent-type"), "PromptCenter")
    assert.equal(auth.split("SignedHeaders=")[1].split(",")[0].includes("agent-type"), false)
  }
  // Asked again the same day: in already, and nothing is claimed twice.
  const again = await plugin.auth.checkin(async () => makeAuth(cred))
  assert.equal(again.outcome, "done")
  assert.equal(calls.filter((c) => c.url === x.OPS_CLAIM_URL).length, 1)
})

test("a claimed check-in is kept, and the usage card says when those credits run out", async () => {
  const cred = await makeCred()
  const ledgerPath = path.join(ledgerDir, "integrated.json")
  const ops = opsFetcher({ item: daily() })
  const fetcher = async (url, init) => {
    if (String(url).endsWith("/snap-manager/v1/statistics/plugin")) {
      return new Response(JSON.stringify({
        metrics: [
          { name: "usageTotalPackageCredit", package_credit_amount: 6500, package_credit_remain: 6500 },
          { name: "usageBonusPackageCredit", package_credit_amount: 1000, package_credit_remain: 1000 },
        ],
      }), { status: 200 })
    }
    if (String(url) === x.BENEFIT_BALANCE_URL) return new Response("", { status: 404 })
    return ops.fetcher(url, init)
  }
  const plugin = await CodeArtsAuthPlugin({ client: {} }, { fetch: fetcher, ledgerPath })
  const r = await plugin.auth.checkin(async () => makeAuth(cred))
  assert.equal(r.outcome, "claimed")
  assert.equal("grant" in r, false)
  const kept = JSON.parse(fs.readFileSync(ledgerPath, "utf8"))
  const [grant] = Object.values(kept)[0]
  assert.equal(grant.credit, 1000)
  assert.equal(Date.parse(grant.expiresAt) - Date.parse(grant.at), 30 * 86_400_000)

  const usage = await plugin.auth.usage(async () => makeAuth(cred))
  const bonus = usage.windows.find((w) => w.name === "赠送积分包")
  assert.equal(bonus.runsOutAt, grant.expiresAt)
  assert.equal(bonus.runsOut, 1000)
})

test("grantExpiry takes the vendor's date when the claim gives one", () => {
  const at = Date.parse("2026-10-21T00:00:00Z")
  assert.equal(x.grantExpiry({}, at), at + 30 * 86_400_000)
  assert.equal(x.grantExpiry({ expire_time: "2026-11-15 00:00:00" }, at), Date.parse("2026-11-14T16:00:00Z"))
})

test("checkin skips the confirm when the claim answers no id", async () => {
  const cred = await makeCred()
  const ok = (data) => new Response(JSON.stringify({ code: 0, data }), { status: 200 })
  const { fetcher, calls } = opsFetcher({ item: daily() }, { claim: () => ok({ id: null }) })
  const { grant, ...r } = await x.dailyCheckin(cred, fetcher)
  assert.deepEqual(r, { outcome: "claimed", credit: 1000, message: "+1000 积分" })
  assert.equal(grant.credit, 1000)
  assert.equal(calls.some((c) => c.url === x.OPS_CONFIRM_URL), false)
})

test("checkin tells done, inactive and ineligible apart", async () => {
  const cred = await makeCred()
  for (const status of ["CLAIMED", "CONFIRMED", "CONSUMED"]) {
    const { fetcher, calls } = opsFetcher({ item: daily({ claimable: false, status }) })
    assert.equal((await x.dailyCheckin(cred, fetcher)).outcome, "done")
    assert.equal(calls.length, 1)
  }
  assert.equal((await x.dailyCheckin(cred, opsFetcher({}).fetcher)).outcome, "inactive")
  const ineligible = await x.dailyCheckin(cred, opsFetcher({ item: daily({ claimable: false, status: null }) }).fetcher)
  assert.equal(ineligible.outcome, "ineligible")
})

test("checkin looks again after a refused claim, and reports a real failure", async () => {
  const cred = await makeCred()
  const refused = (s) => {
    s.item = { ...s.item, claimable: false, status: "CLAIMED" } // claimed elsewhere meanwhile
    return new Response(JSON.stringify({ code: 1001, message: "already claimed" }), { status: 200 })
  }
  assert.equal((await x.dailyCheckin(cred, opsFetcher({ item: daily() }, { claim: refused }).fetcher)).outcome, "done")

  const boom = () => new Response(JSON.stringify({ code: 500, message: "活动太火爆" }), { status: 200 })
  const failed = await x.dailyCheckin(cred, opsFetcher({ item: daily() }, { claim: boom }).fetcher)
  assert.deepEqual(failed, { outcome: "failed", message: "领取失败：活动太火爆" })

  const listFailed = await x.dailyCheckin(cred, opsFetcher({ item: daily(), listStatus: 401 }).fetcher)
  assert.equal(listFailed.outcome, "failed")
  assert.match(listFailed.message, /HTTP 401: APIG\.0301/)
})

test("checkin without a sign-in fails without calling the vendor", async () => {
  const plugin = await CodeArtsAuthPlugin({ client: {} }, { fetch: async () => { throw new Error("no network") } })
  assert.deepEqual(await plugin.auth.checkin(async () => ({ type: "api", key: "k" })), { outcome: "failed", message: "not signed in" })
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
