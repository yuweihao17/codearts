# CodeArts 插件设计说明

## 一、参考插件与参考实现

### 1. 结构模板：`packages/workbuddy`

从 `magpie-community/plugins` 仓库中，与本任务结构最相近的模板是
**`packages/workbuddy`（`@magpie-community/opencode-workbuddy-auth`）**：

| 维度 | WorkBuddy | CodeArts | 结论 |
| --- | --- | --- | --- |
| 厂商性质 | 国内云厂商的编码订阅 | 华为云码道编码订阅 | 同类 |
| 接口协议 | OpenAI 兼容 Chat Completions | OpenAI 兼容 Chat Completions | 一致 |
| SDK | `@ai-sdk/openai-compatible` | 同 | 一致 |
| 插件形态 | provider + auth + config + usage | 同 | 一致 |
| 差异点 | 浏览器设备流登录 | **PKCE OAuth + 请求签名** | 需替换 auth 与 fetch |

### 2. 真实流程参考：`Ebony-Vinyl/dsh-our-free-model` 的 CodeArts 通道

CodeArts **不是 API Key** 登录：请求必须用临时 AK/SK/security-token 做
SDK-HMAC-SHA256 签名，凭据由 OAuth 换取。因此本插件的 auth 与签名逻辑直接对齐
该项目的 CodeArts 通道（`vendor/channel-pack/src/`）：

| 本插件实现 | 参考文件 | 作用 |
| --- | --- | --- |
| `startOAuthFlow` / `startOAuthCallbackServer` / `buildOAuthLoginUrl` | `login.ts` | 新式 IAM OAuth：本地回调服务器 + portal 授权 URL |
| `generatePkcePair` / `generateDpopKeyPair` / `signDpopJws` / `requestToken` | `oauth.ts` | PKCE 与 DPoP（ES256）token 交换 |
| `signRequestHuawei` / `buildCanonicalRequest` | `sign.ts` | 华为 SDK-HMAC-SHA256 请求签名 |
| `fetchRemoteModels` / `parseModelInfo` / `normalizeModelId` | `models.ts` | 两个签名端点的模型列表 |
| `signedFetch`（benefit 头、Chat-Id/Session-Id/lang） | `llm-adapter.ts` | Chat Completions 请求构造 |
| `usageFromStatistics` | `codearts-credits.ts` | 积分套餐用量 |

辅助参考：`packages/cline`、`packages/zen-free`（用于确认 `loader` 返回值形态与
飞行中改写请求的写法）。

## 二、主要改造内容（相对 WorkBuddy）

1. **auth 方式：浏览器设备流 → PKCE OAuth + DPoP**
   - `methods` 改为 `[{ type: "oauth", label: "Sign in with Huawei Cloud", authorize }]`；
     `authorize()` 返回 `{ url, instructions, method: "auto", callback }`，由 magpie
     打开授权页并回调 `callback()`。
   - `authorize()` 内部：起 `127.0.0.1` 回调服务器（端口 ≥ 10000，对齐真实插件的
     端口要求）→ 生成 PKCE 对与 ES256 DPoP 密钥对 → 返回 portal 授权 URL。
   - 回调收到 `code` 后向 STS 换取临时凭据；也兼容 portal 回退到旧 ticket 流程的
     `secret` 分支。

2. **请求签名：Bearer API Key → SDK-HMAC-SHA256**
   - `loader` 不再返回 `apiKey`，而是返回 `baseURL` + 自定义 `fetch`，在 `fetch` 内
     用 `signRequestHuawei` 给请求签名。
   - benefit 模型附带**参与签名**的 `maas_type: benefit` 头；非 sign 的 `Chat-Id` /
     `Session-Id` / `lang` 头在签名后追加。

3. **凭据与续期**
   - 完整凭据（AK/SK/ST/`expires_at` + `refresh_token` + `code_verifier` +
     `dpop_private_key_jwk`）以 JSON 存在账号的 `access` 字段。
   - `auth.refresh` 用 `refresh_token` 复用同一 `code_verifier` 与 DPoP 私钥续期；
     对忽略 `auth.refresh` 的宿主（OpenCode / 旧 magpie）另在 `fetch` 内做带单飞
     的临期续期兜底。

4. **端点固定为华为云 cn-north-4**
   - Chat Completions 基址 `https://snap-access.cn-north-4.myhuaweicloud.com/api/v2`。

5. **模型目录与用量**
   - 目录换成码道真实模型，并带真实上下文窗口（见 README）。
   - 实时列表来自 `opengw gateway/config`（benefit 模型）∪ `snap-access
     /v1/model/builtin`（常规模型）；对 `-VL` 视觉模型过滤。末尾 `-NNNN` 日期后缀只在
     展示名与上下文窗口查表时去掉，下发给网关的 id 保持原样（见 0.2.0 一节）。
   - `usage` 读 `statistics/plugin` 的积分口径，映射为 magpie 的 `{plan, windows}`。

6. **零依赖**
   - 签名与 PKCE/DPoP 全部用运行时内置 WebCrypto（`globalThis.crypto.subtle`）
     实现，不引入 `jose`；唯一的内置模块依赖是 `node:http`（本地回调服务器）。

## 二之二、0.2.0：让它真正可用（修复上游 issue #1 / #5 / #7）

社区（issue #1 讨论、PR #6、`ReachForStar/codearts`）在真实网关上实测得出的结论，
本版逐条落实；与之冲突的取舍在下面单独说明。

| 问题 | 现象 | 处理（`index.mjs`） |
| --- | --- | --- |
| 并发会话上限 `TM.00001041` | 每账号 3 个会话，会话结束后还占位约 60 秒；网关按 `x-ot-session-id` 区分会话，旧代码不发这个头，于是每个请求都是一个新会话 | `accountSessionIds`：账号级稳定会话 id（登录时生成 `session_id`，续期保留，跨进程一致），按码道客户端（`agentkernelServer` 的 `getInferhubHcHeaders`）发送 `x-ot-session-id` / `user-session-id` 与每请求随机的 trace 头；`createConcurrencyGate`：账号内在途 ≤ 3，许可持有到响应体结束；`signedFetch`：400 或 200 首事件里的 `TM.00001041` 带抖动退避重试（每次重签），预算耗尽返回 `429` 让 magpie 切账号 |
| 网关排队 | `429` + `queue-status: queued` + `trace-id` / `retry-after` | `waitInQueue`：照客户端轮询 `GET /api/v1/concurrency/trace-queues/{trace-id}`，`promoted` 后重发原请求，`not_found` / `error` / 超时返回 `429`，放弃时 `DELETE` 退出队列 |
| `InferHub.4004.200 benefit not found` | 免费模型要先领取当日权益：码道内核 `loadBenefitModels` 先 `getGatewayConfig`，再 `claimBenefit`（`POST opengw /api/v1/benefit/claim`，`error_code === "0000"` 为成功），失败就不加载免费模型；插件从没领取过 | `ensureBenefitClaimed`：每个北京自然日每账号领一次（单飞，被拒一小时后再试，连不上沿用上次结果），成功才把 `gateway/config` 的模型列为免费并发 benefit 头；仍收到 `4004` / `4005` 且模型在内置列表中时去掉头重发，并按账号记住 |
| magpie 里倍率不对 / 免费标记不对 | 插件从没上报 `rate`；免费标记落回静态兜底 | `fetchAgentModels`：`/v1/agent-center/agents/useragents` 找主智能体（`original_id` 为 `build`，旧列表叫 `CodeAgent`；客户端的 `CODE_AGENT_AGENT_ID`，日志中为 `a8bcb36232554267a5142361cc25a393`，列表读不到时用它），再读 `agents/detail` 的 `gpts.models`（客户端 `doGetTaskListInfoRequest` 同款），某个智能体没有模型就试下一个，`credit[].ratio_display` → `rate`，`thinking_type` → 推理模型，`context_window` / `max_tokens` → 上限；`free` 只在当日权益领取成功时为真 |
| 积分有效期 | `statistics/plugin` 只给各桶余额；每批积分的到期时间在控制台「套餐与用量 → 获取明细」 | `fetchCreditBatches`：照控制台的请求（`/portal/snap-manager/*`、`/portal/promptcenter/*` 即 snap-access 的 `/snap-manager/*`、`/*`），`POST /snap-manager/v1/package/credit/page`（`{packageTypes:["basic","ondemand"]}` 与 `["bonus"]`）取 `expiredTime`，`GET /v1/ops/credit/overview` → `/v1/ops/credit/campaign/{id}` 取每笔 `expireAt`；套餐批次的到期即月度重置（`resetsAt`），其余按最早到期的一天给 `runsOutAt` / `runsOut`（总积分不含套餐批次）；10 分钟缓存，签到后失效；读不到时退回本地签到账本（领取 + 30 天）与 `end_date`；免费额度窗口按北京零点重置 |
| 签名查询串 | 多参数查询未排序即签名 | `canonicalQuery`：按 key、value 排序并 RFC 3986 编码 |
| 没有输出 | 推理模型默认把思考写进 `content` | `prepareChatBody` 默认注入 `thinking: { type: "enabled" }`，被拒时去掉重发 |
| 看似成功实则失败 | 额度用尽 / 模型未注册以 200 + SSE 内嵌 `error_code` 返回 | `peekAnswer` + `classifyHead` 先读到首个有内容的事件再交出；纯错误换算为 `429`（额度、限流）/ `502`，带厂商原话 |
| 模型 id 前缀 | 宿主下发 `codearts/xxx` | `upstreamModelId` 去前缀 |
| 输出上限 | `max_completion_tokens` > 65536 报 `RANGE_VALIDATOR` | 声明 `limit.output = 65536`，并在请求里压到 65536 |
| 临时凭据过期 | `401 APIG.0301` / `400 APIG.0602` 后账号一直失败 | loader 单飞续期并重发一次；续期前先读存储，宿主已续过就直接接管，避免一次性 refresh_token 被用两次；`STS5.1806` 等永久失败才标记登录失效 |
| 续期写回丢字段 | `client.auth.set` 整条替换账号记录 | `persistCredential` 带上原记录（含 `accountId`） |
| 重复登录多出账号 | STS 不返回用户信息，`accountId` 恒空 | `accountIdentityOf` 从 `refresh_token` 的 `user_profile` 取 `principal_urn` |
| 免费模型 id | 带日期后缀的才是免费模型，去后缀后是另一个付费模型 | 按原始 id 下发与去重；`gateway/config` 的模型一律标 benefit 与 `free: true`；目录去掉调不通的 `GLM-5` |
| 用量窗口误伤路由 | 基础积分包用完就让还有余额的账号被暂停 | 只有「总积分」参与路由，其余桶与「免费额度」窗口 `aside: true` |

**计费取舍。** 实测非流式请求返回 token 却不扣积分。有方案利用它绕开流式会话上限
（拿不到槽位就降级非流式，或免费模型全程非流式）。本插件不这样做：所有对话都以
`stream: true` 发往上游正常计量，调用方要 JSON 时由 `foldAnswer` 折叠回
`chat.completion`。代价是会话上限只能排队等待，不能绕过。

**每日签到（issue #5）。** `auth.checkin(getAuth)` 是 magpie 自己的 hook（OpenCode 忽略），
宿主调用前会先续期账号，每个北京自然日问一次，`failed` 30 分钟后重试。协议直接取自本机
安装的码道客户端 `workbench.desktop.main.js` 的 `ActivityWelfarePane`：

1. `GET {snap}/v1/ops/delivery?channel=IDE` → `data.items[]`，取 `type === "USER_LOGIN"`；
2. `claimable === false` 且 `status ∈ {CLAIMED, CONFIRMED, CONSUMED}` → `done`；
   其余不可领 → `ineligible`；没有该活动 → `inactive`；
3. `POST {snap}/v1/ops/claim`，体 `{ campaignId, channel: "IDE" }`；
4. 返回 `data.id !== null` 时 `POST {snap}/v1/ops/confirm`，体 `{ campaignId }`；
5. 领取被拒时再读一次活动列表，若已是已领取态（别处刚领过）按 `done` 处理。

请求与用量接口同样用 SDK-HMAC-SHA256 签名，`Agent-Type` / `X-Language` 在签名之后追加
（参与签名会被网关判为验签失败）。

## 三、实现步骤

1. 建包（本仓库为单包，插件直接放在仓库根目录），`package.json` 声明
   `magpie` 元数据与 `type: module`。
2. `index.mjs` 导出插件函数 `CodeArtsAuthPlugin({ client }, options)`，返回
   `{ config, provider, auth }`：
   - `config`：用 `??=` 注册 `codearts` provider 与 `CATALOG` 模型，不覆盖用户配置。
   - `provider.models`：签名拉取两个远端端点，失败回退目录。
   - `auth`：`methods` 提供 OAuth 登录，`loader` 签名请求，`refresh` 续期，
     `usage` 汇报用量。
3. `README.md` 写安装 / 登录 / 使用 / 已知限制。
4. `index.test.mjs` 覆盖签名、PKCE/DPoP、凭据往返、远端列表、loader 签名、
   续期、用量、回调服务器，以及 0.2.0 的会话上限重试、并发闸门、流式折叠、内嵌错误
   换算、凭据自愈、会话头、网关排队、benefit 领取与回退、倍率、积分重置与签到账本、每日签到，
   全程不联网（`node --test`，79 项）。
5. `registry-entry.json` 提供加入 `magpie` 插件市场的登记项。

## 四、目录

```
./  (仓库根 = 插件目录)
├── package.json
├── index.mjs
├── index.test.mjs
├── registry-entry.json
├── README.md
└── DESIGN.md
```
