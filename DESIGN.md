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
     /v1/model/builtin`（常规模型）；对 `-VL` 视觉模型过滤，并去掉末尾 `-NNNN`
     日期后缀。
   - `usage` 读 `statistics/plugin` 的积分口径，映射为 magpie 的 `{plan, windows}`。

6. **零依赖**
   - 签名与 PKCE/DPoP 全部用运行时内置 WebCrypto（`globalThis.crypto.subtle`）
     实现，不引入 `jose`；唯一的内置模块依赖是 `node:http`（本地回调服务器）。

7. **会话与错误自愈**（针对 issue #1 的「完全无法开始对话」）
   - 上游网关按 `Chat-Id` 计并发会话，每账号上限 **3 个**，会话在响应完成后还要
     存活一段时间。旧版每个请求都随机生成 `Chat-Id`，请求一密集就把 3 个槽位占死，
     之后每个请求都吃 `400 TM.00001041`（并发会话数已达上限）。
   - `Chat-Id` / `Session-Id` 从账号凭据**派生**（`sha256("codearts:" + access_key_id)`
     取两段 32 位 hex）：实测服务端按 `Chat-Id` 复用会话，同 id 连发/并发——含一条
     流式一条非流式、以及同一会话 4 路并发（答案零串扰）——都不再累计槽位；派生使
     **所有进程、所有设备**上的同一账号共享同一个会话，插件自身永远只占一个槽，
     跨进程（CLI / TUI / 常驻网关）也不再互相挤占。id 仅在 STS 轮换 AK 后变化。
   - 对残余的 `TM.00001041`（同账号其它端/官方客户端占槽）在 `signedFetch` 里做
     带抖动的退避重试（1s→2s→4s→6s→8s→10s→12s→15s 均匀轮询，槽位自行回收、
     每次重试重新签名以保证 `x-sdk-date` 新鲜）；其它 400 原样透传；`AbortSignal`
     在重试间隙生效。
   - `401`（IAM 报 `APIG.0301 verify ak sk signature fail`，即临时凭据过期/被轮换）
     触发一次**强制续期 + 重试**（与临期续期共用单飞，失败后 10s 冷却），免得一次
     错过的定时续期把账号打死到手动重新登录；续期救不回来才标 `X-Magpie-Sign-In:
     expired`。
   - 已知限制：无额度账号请求 `openpangu-2.0-flash` 会得到 `content: null` /
     `completion_tokens: 0` 的 200 响应（benefit 档无 entitlement，见 issue #1）；
     是否隐藏该模型因账号而异，暂不擅自过滤。

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
   续期、用量、回调服务器，全程不联网（`node --test`，37 项）。
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
