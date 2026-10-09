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
   续期、用量、回调服务器，全程不联网（`node --test`，28 项）。
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
