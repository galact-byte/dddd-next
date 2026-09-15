# Issue #1：自定义 FOFA API 调研

> 实施状态（2026-09-15）：已按本方案实现 `FOFA_SERVER`、官方默认地址、FOFA 适配器与部分结果保留，仍要求邮箱和 Key。用法见 [README](../README.md#fofa-官方与自建接口)。以下“现状”保留调研时的基线；当前实现已修复其中的固定地址及错误丢弃问题。

## 结论与需求边界

[Issue #1](https://github.com/galact-byte/dddd-next/issues/1) 仅提出“增加自定义 fofa api”，没有提供服务地址、鉴权方式或响应示例。最合理的第一步是支持 **FOFA 协议兼容服务的自定义服务器地址**；不能据此承诺兼容任意第三方资产接口。

建议沿用 FOFA 官方 GoFOFA 的 `FOFA_SERVER` 命名，通过现有 `.env` 设置，不另加重复的 CLI 参数。该调研阶段没有访问真实 FOFA 账号、消耗查询额度或联系 Issue 作者。

## 调研时已核实的现状

| 事实 | 源码依据 |
| --- | --- |
| 项目目前只文档化邮箱和 Key，没有服务器地址配置 | [凭证示例](../.env.example) |
| 普通测绘查询由 pipeline → 本地 uncover 封装 → projectdiscovery/uncover v1.2.1 执行 | [pipeline.go](../internal/app/pipeline.go)、[uncover.go](../internal/discovery/uncover/uncover.go)、[go.mod](../go.mod) |
| 请求地址是常量 `https://fofa.info/api/v1/search/all`；Options 没有端点字段，Agent 也无配置字段 | [上游 v1.2.1 FOFA Agent](https://github.com/projectdiscovery/uncover/blob/v1.2.1/sources/agent/fofa/fofa.go)、[Service/Options](https://github.com/projectdiscovery/uncover/blob/v1.2.1/uncover.go) |
| 本次读取的上游 main 仍然硬编码该地址 | [固定提交源码](https://github.com/projectdiscovery/uncover/blob/8275048441329a9ce0622bead7b37826d34e5d7d/sources/agent/fofa/fofa.go) |
| uncover 要求邮箱与 Key 同时存在，但其 FOFA 搜索请求只发送 Key | 同上 Agent；[Provider](https://github.com/projectdiscovery/uncover/blob/v1.2.1/sources/provider.go) |
| 查询错误被本地封装的 `if r.Error != nil { continue }` 丢弃；pipeline 收到错误则跳过整次查询 | [uncover.go](../internal/discovery/uncover/uncover.go)、[pipeline.go](../internal/app/pipeline.go) |
| `.env` 加载顺序是进程环境优先，其次工作目录文件，最后程序目录文件，已有值不覆盖 | [main.go](../cmd/dddd/main.go)、[config.go](../internal/config/config.go) |
| 官方 GoFOFA 支持 `FOFA_SERVER`，默认 `https://fofa.info`；邮箱是可选的旧配置 | [fromenv.go](https://github.com/FofaInfo/GoFOFA/blob/7074e9b951f779c604e8b4c555dbfc6dc3c9f064/fromenv.go)、[client.go](https://github.com/FofaInfo/GoFOFA/blob/7074e9b951f779c604e8b4c555dbfc6dc3c9f064/client.go) |
| 官方 SDK 通过标准 URL 编码拼接 `/api/<version>/<接口>`，Key 必填、邮箱有值才发送；构造客户端会先请求账号信息 | [request.go](https://github.com/FofaInfo/GoFOFA/blob/7074e9b951f779c604e8b4c555dbfc6dc3c9f064/request.go)、上述 client.go |

注意：这些是各份源码的行为，不代表已经验证所有第三方服务，或证明当前所有 FOFA 套餐的权限。

## 建议的用户配置

```dotenv
# 留空时使用 https://fofa.info；自定义服务须兼容 FOFA 搜索协议。
FOFA_SERVER=https://fofa-gateway.example.com
FOFA_EMAIL=your-email@example.com
FOFA_KEY=your-service-key
```

查询继续使用既有的 `-fofa`、`-t` 和 `-limit` / `-fmc`，无需改变目标输入入口。`FOFA_SERVER` 表示服务器基础地址，不是带 Key 的完整请求 URL，也不是 HTTP 代理；`-proxy` 继续表示网络代理。

建议明确允许基础地址带路径前缀，例如 `https://gateway.example.com/fofa` → `/fofa/api/v1/search/all`，保留前缀并统一处理末尾斜杠。拒绝无主机、非 HTTP(S)、带 userinfo、query 或 fragment 的配置，避免隐含鉴权和路径歧义；使用 `url.Values` 编码请求参数。

第一版兼容契约：GET 搜索接口，`key`、`qbase64`、`fields=ip,port,host`、`page`、`size`、`full` 参数，返回 FOFA 风格的 `error`、`errmsg`、`size`、`results`；结果列遵从请求的 fields 顺序。不同路径、Bearer 鉴权或另一种 JSON 结构需提供接口文档再适配。

## 实现方案比较

| 方案 | 评估 |
| --- | --- |
| 只加环境变量或升级 uncover | 无法改变现有常量地址；已核对的上游 main 也不支持 |
| fork uncover / 修改模块缓存 | 为一个地址维护 fork 成本偏高；修改缓存不可交付，不采用 |
| 用 Transport 偷换请求地址 | 请求 URL、Host、TLS 和错误信息易不一致，而且当前包装没有直接的 transport 注入入口，不推荐 |
| 引入官方 GoFOFA SDK | 有现成服务器配置，但会增加依赖和账号信息前置请求；兼容中转未必实现账号接口，不作为首选 |
| 在本地实现可配置 FOFA Agent，接入现有 uncover Service | **保留现有邮箱 + Key 约束时改动最小，推荐第一版采用**；复用 Session 的代理、超时、限速和其他引擎编排 |
| 专用 FOFA 客户端独立执行，再合并其他 uncover 引擎结果 | 如果明确需要仅 Key 鉴权，较合理；可以摆脱 Provider 的邮箱要求，但需要自行处理限速、代理和多引擎合并，范围更大 |

### 推荐落点

1. `.env.example` 和 README 增加唯一配置项 `FOFA_SERVER`；默认行为仍访问官方服务器。
2. 在 `internal/discovery/uncover` 内增加局部 FOFA Agent，实现 `sources.Agent`，复用 `sources.Session`；无需新增依赖。本地封装已有 `types.Asset` 投影，可继续复用。
3. `pduncover.New` 创建后、`Execute` 前，按 `agent.Name() == "fofa"` 替换该实例的 `Service.Agents` 项；上游公开了该列表，其他引擎保留。服务器配置通过本地 Options 注入，环境读取集中在调用边界，不在请求过程中反复读取，不修改进程全局 URL。
4. 官方和自定义地址使用同一套本地 FOFA Agent，避免维护两种解析及错误行为。保持官方默认地址、现有 `full=false` 和查询字段约定。
5. `FOFA_SERVER` 只在实际启用 FOFA 时校验；无关的普通 IP 扫描和仅 Hunter/Quake 查询不被 FOFA 配置阻塞。
6. 第一版保留 uncover 对邮箱 + Key 的要求，并在文档准确注明。不能通过伪造邮箱或注入假 Key 绕过 Provider。若要直接支持官方目前的仅 Key 方式或某个中转仅 Key 的用法，应选择专用客户端路线，不能只删 Agent 的邮箱检查，因为 Provider 也有约束。

## 本次功能必须一并处理的边界

- **错误可见**：HTTP 401/403/429/5xx、API `error=true`、HTML 错误页、无效 JSON、网络超时要有来源明确的错误。区分请求失败与成功但零条结果。
- **部分成功**：不能简单把所有错误返回给当前 pipeline 后就 `continue`，否则会丢弃同次查询中其他引擎或已完成页面的结果。让 Query 返回部分资产及错误，并让 pipeline 先记录错误、再消费已有资产；Agent 初始化错误也要进入可观察的结果路径，避免只依赖上游日志。
- **响应边界**：检查列数、端口范围及 IP/Host 内容；畸形行不能像上游直接索引三列而 panic。限制响应体大小，对空页、总数和请求上限设置明确停止条件。
- **额度与取消**：保留限速和有界重试，鉴权失败不重试；分页总结果不得超过 limit，取消立即结束。首次 size 和后续页大小应遵循服务分页语义；固定页大小并截断返回数比在最后一页改变 size 更稳妥，测试跨页是否重复或遗漏。
- **凭证保护**：错误和审计不输出含 Key 的完整 URL，第三方响应文本也要限长和脱敏；默认拒绝跨源重定向和 HTTPS 降级，防止端点重定向带走查询凭证。保持 TLS 校验开启，自定义失败不静默回退官方地址。
- **结果接入**：`host` 可能是完整 URL，进入端口探测前应明确提取 hostname/port，保留原 URL；用实际 FOFA 风格结果覆盖这条链路，不能只测返回条数。

## 验证计划

使用 `httptest.Server` 和假 Key，无需真实账号或查询额度：

1. 默认地址、自定义地址、路径前缀、尾斜杠；无效配置不发送请求。
2. 中文及带 `+ / = &` 的查询/Key 正确编码、解码；请求参数与约定一致。
3. 正常结果、零结果、跨页结果、limit 截断、空页结束、取消及超时。
4. 鉴权失败、限流、错误 JSON、畸形行、过大响应和跨源重定向；日志不含凭证。
5. FOFA 失败 + 其他引擎成功、后续页失败 + 先前页面成功，仍保留已得资产。
6. 带 URL 的 host 正确转成下游目标，本机模拟接口 → 结果归一化 → 本机服务探测可以完整结束。
7. `.env` 优先级及未选择 FOFA 时配置不干扰其他路径；运行 `go test ./...`、`go vet ./...` 和 Windows 构建。

## 待真实服务信息确认

若 Issue 作者只想更换兼容服务器域名，上述第一版足够形成可测试的实现。若要承诺其特定服务可用，还需该服务的公开接口文档或脱敏请求/响应示例，至少确认路径、鉴权、是否要求邮箱、fields 顺序和分页约定。当前 Issue 没有这些信息，调研不能把“支持配置地址”等同于“已验证该中转服务”。
