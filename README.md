# opencode-codearts-auth

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
    `code_verifier` 与 DPoP 私钥）换新凭据。
4.  **模型列表 / 用量**：登录后用签名 GET 拉取账号真实模型列表与积分套餐用量。

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

-   模型列表中会出现 `GLM-5.2`、`GLM-5.1`、`GLM-5`、`glm-5.3-flash`、  
    `openpangu-2.0-flash/pro`、`deepseek-v4-flash/pro`、`deepseek-v4.1-flash` 等；  
    登录后会以账号真实返回的列表为准。
-   CLI 里可用 `codearts --model codearts/GLM-5.2` 之类方式指定。

## 说明与已知限制

-   **模型目录**是出厂默认（上下文窗口取自码道模型卡：`GLM-5.2` = 202752、  
    `glm-5.3-flash` / `deepseek-v4-flash` / `deepseek-v4-pro` = 1048576、  
    `deepseek-v4.1-flash` = 1000000）。账号能返回实时列表时会覆盖 `id`/`name`。
-   **benefit（免费额度）模型**：`glm-5.3-flash`、`deepseek-v4.1-flash` 等需要把  
    `maas_type: benefit` 作为**参与签名**的请求头发送，否则后端返回  
    `InferHub.002002009.404 model is not registered`。插件会从 `gateway/config`  
    动态识别这批模型，冷启动时用静态兜底集合。
-   **用量**是尽力而为：读取 `snap-manager/v1/statistics/plugin` 的积分口径  
    （`usageTotalPackageCredit`），把已用比例显示为一条「total credits」窗口；  
    取不到时在用量卡片显示一条错误，不影响对话。
-   **区域 / 端点**：当前固定华为云 `cn-north-4`（与真实插件一致）。
-   本插件不内置 MCP / 中间件，仅做模型接入。
-   依赖：无（签名、PKCE、DPoP 都用运行时内置的 WebCrypto，无需 `jose` 等三方库）。

## License

MIT