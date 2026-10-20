# opencode-codearts-auth

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](./LICENSE)
[![magpie plugin](https://img.shields.io/badge/magpie-plugin-8A2BE2)](https://usemagpie.ai/docs/zh/plugins)
[![OpenCode plugin](https://img.shields.io/badge/OpenCode-plugin-blue)](https://opencode.ai)
![no dependencies](https://img.shields.io/badge/dependencies-none-brightgreen)
![tests](https://img.shields.io/badge/tests-79%20passing-success)

[Huawei Cloud CodeArts (华为云码道 代码智能体)](https://www.huaweicloud.com/product/codearts.html)  
作为 magpie / OpenCode 的 provider 插件：用**华为云 OAuth 授权登录**接入码道的模型  
（盘古 openPangu、DeepSeek、GLM 等）。

CodeArts 的模型网关确实是 OpenAI 兼容的 Chat Completions 接口，但它**不接受 API  
Key**：请求要用临时的 AK/SK/security-token 凭据做 *SDK-HMAC-SHA256* 签名，而这些  
凭据要靠 OAuth 登录取得。本插件完整实现了这条链路：

1.  **OAuth（PKCE + DPoP）登录**：`authorize()` 在本机 `127.0.0.1`（端口 ≥ 10000）  
    起一个回调服务器，返回华为云授权页地址给 magpie 打开；浏览器带授权码跳回后，  
    用 `code_verifier` 向 STS 换取临时凭据。登录全程是 PKCE 的，并用一把新生成的  
    ES256（P-256）DPoP 私钥给每次 token 请求签名。
2.  **SDK-HMAC-SHA256 签名**：每次模型请求都由 `loader` 的 `fetch` 用临时凭据签名，  
    和真实 IDE / CLI 的请求一致。
3.  **静默续期**：`auth.refresh` 在凭据过期前用 `refresh_token`（复用同一把  
    `code_verifier` 与 DPoP 私钥）换新凭据；请求遇到临时凭据过期（`401` /  
    `APIG.0602`）时就地续期并重发一次，不再需要手动重新登录。
4.  **并发会话上限**：码道每个账号最多 3 个并发会话（`TM.00001041`），网关按  
    `x-ot-session-id` 区分会话。插件像码道客户端一样发送会话头，同一账号始终是同一个  
    会话；账号内在途请求不超过 3 个，撞到上限时自动退避重试，网关要求排队（`429` +  
    `queue-status: queued`）时按客户端的方式轮询排队状态；等不到才以 `429` 交回  
    magpie，由它切换账号或模型。
5.  **模型列表 / 用量**：登录后拉取账号真实模型列表（含每个模型的**消耗系数**，即  
    magpie 里的倍率）、积分套餐用量、月度重置日、每日免费额度，以及签到积分的过期时间。
6.  **每日签到**：实现 magpie 的 `auth.checkin`，按码道客户端「限时福利 → 每日领取」  
    的同一套接口自动领取每日积分。

## 安装

```sh
magpie plugin add yuweihao17/codearts

```

或本地开发：

```sh
magpie plugin add ./index.mjs

```

## 登录

选择 **Sign in with Huawei Cloud**，浏览器会打开华为云授权页；登录并在授权页确认  
后，浏览器会自动跳回本机的回调地址，插件随即完成登录。无需填写 API Key、也无需  
手动复制任何 token。

## 使用

-   模型列表中会出现 `GLM-5.2`、`GLM-5.1`、`glm-5.3-flash`、  
    `openpangu-2.0-flash/pro`、`deepseek-v4-flash-0731`、`deepseek-v4-pro-0813`、  
    `deepseek-v4.1-flash` 等；登录后会以账号真实返回的列表为准，免费额度模型带  
    「免费」标记。
-   用 `magpie provider test codearts` 验证连通；agent 里选 `codearts/GLM-5.2` 之类即可。

## 每日签到

码道「限时福利 → 每日领取」每个自然日可领一次积分（活动规则见  
[官方说明](https://support.huaweicloud.com/offers-codeartsagent/codeartsagent_offers_0004.html)）。  
插件实现了 magpie 的 `auth.checkin`，与码道客户端的调用完全一致：

1.  `GET /v1/ops/delivery?channel=IDE` 读活动列表，找 `type = USER_LOGIN` 的那一项；
2.  `POST /v1/ops/claim`（`{ campaignId, channel: "IDE" }`）领取；
3.  领取结果带 `id` 时再 `POST /v1/ops/confirm`（`{ campaignId }`）确认，否则积分会停在待确认。

magpie 侧：在 **设置 → 用量 → Plugins** 打开 CodeArts 的「每日自动签到」，magpie 会对每个  
已登录账号每个北京自然日签一次（失败 30 分钟后重试）；也可以在用量卡片上点「立即签到」。  
返回结果：`claimed`（本次领到，附积分数）、`done`（今天已领过）、`inactive`（当前没有  
每日领取活动）、`ineligible`（活动对该账号不可领）、`failed`（附原因）。

## 说明与已知限制

-   **计费口径**：码道只对 SSE 流式回答计量积分（非流式 200 也会返回 token 用量，但不扣  
    积分）。插件因此**总是以流式**向上游发起对话，调用方要的是非流式时再把流折叠回  
    一个普通的 `chat.completion` JSON —— 用量照常计费，不利用这个计费漏洞。
-   **并发会话上限**：上游按账号限 3 个并发会话，流式会话结束后还会占位约 1 分钟。  
    插件会自动排队 / 重试（默认最多等约 150 秒），但同一账号在一分钟内的大量请求仍会  
    变慢；多个账号时 magpie 会在 `429` 后切到下一个账号。
-   **思考与正文分流**：不显式要求时，网关会把推理模型的思考过程塞进 `content`，  
    调用方看到的就是一段自言自语或空回答。插件默认给对话加上  
    `thinking: { type: "enabled" }`（调用方自己传了就不动），思考进 `reasoning_content`、  
    正文进 `content`；个别模型拒绝该参数时会自动去掉重发。
-   **模型 id**：magpie 下发的 `codearts/xxx` 前缀会被去掉；`max_tokens` /  
    `max_completion_tokens` 超过网关上限 65536 时会被压到 65536。
-   **benefit（免费额度）模型**：和码道客户端一样，插件先读 `gateway/config` 的免费模型  
    列表，再 `POST /api/v1/benefit/claim` **领取当日免费权益**（每个北京自然日一次，被拒  
    则一小时后再试）；领取成功，这些模型才标「免费」并带上**参与签名**的  
    `maas_type: benefit` 头；领取失败（`4004` 权益不存在 / 已过期，`4006` 当日名额耗尽）  
    就不列出只能免费调用的模型，同名的普通内置模型照常按积分计费。若网关仍回答  
    `InferHub.4004.200 benefit not found`，且该模型在账号的内置列表里，插件会去掉 benefit 头  
    重发，并记住该账号不再给它加头。带日期后缀的 id 才是免费模型，去掉后缀的  
    `deepseek-v4-flash` 是另一个按积分计费的模型。
-   **倍率（消耗系数）**：取自码道客户端自己的模型列表  
    （`/v1/agent-center/agents/detail` 中主智能体「build」的 `gpts.models[].credit[].ratio_display`），  
    以 magpie 的 `rate` 字段上报；同一份列表还给出是否为推理模型、上下文与输出上限。免费  
    模型不显示倍率。
-   **积分有效期**：读的是码道控制台「套餐与用量 → 获取明细」同一批接口，每批积分都有  
    自己的到期时间：
    -   套餐 / 按需积分包：`POST /snap-manager/v1/package/credit/page`（`expiredTime`）；
    -   活动福利（注册赠送、每日签到等）：`GET /v1/ops/credit/overview` 列出活动，再  
        `GET /v1/ops/credit/campaign/{id}` 读每一笔的 `expireAt`。

    用量卡片上：
    -   「总积分」「基础积分包」是月度配额，重置时间取订阅套餐那一批的到期时间（精确到秒；  
        读不到时退回 `statistics/plugin` 的 `end_date`）；
    -   「赠送积分包」「按需积分包」显示最早一批何时过期、过期多少（同一天到期的几批合在  
        一起算）；「总积分」也显示这个时间（不含会重置的套餐积分）；
    -   各积分桶的 `package_credit_expiring_amount` 写在说明里（「N 即将过期」）；
    -   「免费额度」是每日池，北京时间零点重置。

    批次每 10 分钟读一次（签到后立即刷新）。若这些接口读不到，插件退回自己的签到账本  
    `~/.config/magpie/codearts-checkins.json`（可用环境变量 `MAGPIE_CODEARTS_LEDGER` 改路径；  
    每次签到成功记一笔，按「自领取起 30 天」算到期），这时注册赠送等其他批次没有到期时间。

    > ⚠️ **有效期这部分仍待更多真实数据验证。** 接口与字段是对照码道控制台页面的实际请求  
    > 确认的（签到积分「领取后 30 天到期」与控制台一致），但插件用 AK/SK 签名调用这些接口  
    > 尚未在真实账号上跑过，账号多批积分、部分消耗后的显示也还没验证过。请以码道控制台  
    > 显示为准，发现不一致欢迎反馈。
-   **用量**：读取 `snap-manager/v1/statistics/plugin` 的积分口径，「总积分」决定账号是否  
    可用，基础 / 按需 / 赠送积分包只做明细展示（`aside`）；另读  
    `opengw .../user/tokens/balance` 显示「免费额度」（每日 token 池，只统计免费模型）。
-   **错误回报**：网关把额度用尽、模型未注册等错误放在 HTTP 200 的 SSE 里，插件会换算成  
    `429` / `502` 并带上厂商原话，让 magpie 能切换账号，agent 也能显示真实原因。
-   **重复登录**：账号标识取自 `refresh_token` 里的 `user_profile`，同一账号重新登录会  
    替换原账号，不会多出一个 `codearts#xxxxxx`。
-   `openpangu-2.0-flash` 在部分账号上返回空回答（`content: null`、0 token），属账号权益  
    问题，插件不做过滤。
-   **区域 / 端点**：当前固定华为云 `cn-north-4`（与真实插件一致）。
-   本插件不内置 MCP / 中间件，仅做模型接入。
-   依赖：无（签名、PKCE、DPoP 都用运行时内置的 WebCrypto，无需 `jose` 等三方库）。

### 可调参数

通过 `magpie plugin options <插件名> '<json>'` 传入（插件名见 `magpie plugin list`；都可省略）：

| 选项 | 默认 | 作用 |
| --- | --- | --- |
| `maxInflight` | `3` | 每个账号同时在途的对话请求数 |
| `retryBudgetMs` | `150000` | 撞到 `TM.00001041` 时最多等待多久，超时返回 `429` |
| `retryDelays` | `[2000,4000,6000,8000,10000]` | 重试间隔（毫秒，最后一个值循环使用） |
| `queueBudgetMs` | `300000` | 网关要求排队时最多等多久，超时退出队列并返回 `429` |
| `thinking` | `true` | 设为 `false` 时不注入 `thinking: { type: "enabled" }` |

## English

**opencode-codearts-auth** is a magpie / OpenCode provider plugin that signs you in to
[Huawei Cloud CodeArts (码道)](https://www.huaweicloud.com/product/codearts.html) with
**Huawei Cloud OAuth** (PKCE + DPoP) and exposes its models (openPangu, DeepSeek, GLM, …).

The CodeArts gateway is OpenAI-compatible Chat Completions, but it does **not** accept an API key:
every request must be signed with temporary AK/SK/security-token credentials (*SDK-HMAC-SHA256*),
and those credentials come from an OAuth sign-in. This plugin implements the whole chain —
local-callback PKCE OAuth, per-request SDK-HMAC-SHA256 signing, silent refresh — with **no runtime dependencies**.

### Install

```sh
magpie plugin add yuweihao17/codearts
```

### Sign in

Pick **Sign in with Huawei Cloud** (or run `magpie plugin login codearts`). Your browser opens the
Huawei Cloud consent page; after you approve, it redirects back to a local `127.0.0.1` callback and
the plugin finishes signing in. No API key, no copy-paste.

### Use

Models appear as `codearts/GLM-5.2`, `codearts/glm-5.3-flash`, `codearts/openpangu-2.0-flash`,
`codearts/deepseek-v4.1-flash`, … Verify with `magpie provider test codearts`, or pin one with
`codearts --model codearts/GLM-5.2`.

### Daily check-in

The plugin implements magpie's `auth.checkin` hook with the same three calls the CodeArts IDE's
「限时福利 → 每日领取」 makes (`/v1/ops/delivery` → `/v1/ops/claim` → `/v1/ops/confirm`). Turn on
*Auto check-in* for CodeArts under **Settings → Usage → Plugins**, or press *Check in now* on its usage card.

### Notes

- **Session cap.** CodeArts allows 3 concurrent sessions per account (`TM.00001041`) and tells sessions
  apart by `x-ot-session-id`; a session holds its slot for about a minute. Like the CodeArts agent, the plugin
  sends one stable session id per account (plus a fresh trace per request), keeps at most 3 chats in flight
  per account, retries a cap answer with backoff (up to ~150 s), and waits out the gateway's own queue
  (`429` + `queue-status: queued`) by polling it the way the agent does — only then is a `429` handed to magpie.
- **Free models** are the account's live `gateway/config` list, and only once today's benefit has been claimed
  (`POST /api/v1/benefit/claim`, once a Beijing day, as the CodeArts agent does); a `benefit not found` answer for
  a model the account also lists as a builtin model is sent again without the benefit header (billed as credits).
- **Credit rates** (the IDE's 消耗系数) come from the main agent's ("build") own model list
  (`/v1/agent-center/agents/detail` → `credit[].ratio_display`) and are reported as magpie's `rate`.
- **Credit expiry.** Read from the same calls as the CodeArts console's 获取明细 tab: package batches
  (`POST /snap-manager/v1/package/credit/page`, `expiredTime`) and campaign grants (`/v1/ops/credit/overview` →
  `/v1/ops/credit/campaign/{id}`, `expireAt`). The monthly buckets reset when the plan's batch ends; the bonus and
  on-demand buckets (and the total) show when their soonest batch lapses and how much. When those calls can't be
  read, a local check-in ledger (`~/.config/magpie/codearts-checkins.json`, or `MAGPIE_CODEARTS_LEDGER`; 30 days
  per claim) stands in. **Still to be verified on more real accounts** — trust the CodeArts console where they differ.
- **Metering.** CodeArts meters only streamed answers, so every chat goes upstream as a stream and is folded
  back into a plain `chat.completion` when the caller asked for JSON. Usage is billed as normal.
- **Reasoning.** The plugin sends `thinking: { type: "enabled" }` unless the caller set it, so reasoning
  arrives in `reasoning_content` and `content` is only the reply.
- **Self-healing sign-in.** A stale temporary credential (`401`, `APIG.0602`) is renewed once and the request
  re-sent; only a refresh token that is gone for good marks the account.
- Errors the gateway hides inside a `200` stream (spent quota, unknown model) come back as `429`/`502` with the
  vendor's message. The `codearts/` model prefix is stripped and output budgets are clamped to 65536.
- `benefit` (free-quota) models are detected automatically and sent with a signed `maas_type: benefit` header;
  the free daily token pool shows up as its own usage window.
- Region/endpoint is fixed to Huawei Cloud `cn-north-4`.
- No MCP / gateway middleware — model access only.

## License

MIT — see [LICENSE](./LICENSE).