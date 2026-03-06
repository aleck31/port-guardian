# EC2 SSH Guardian — 架构评估

## Web 层方案对比

### 方案 A：Python + Chalice

Chalice 是 AWS 官方的 Python Serverless 微框架，通过装饰器定义路由，自动生成 API Gateway + Lambda 部署。

- 前端：静态 HTML/JS 文件通过 API Gateway 或 S3 托管
- 后端：Chalice 应用，Lambda 运行 Python 代码
- 认证：API Gateway Cognito Authorizer（Chalice 内置 `CognitoUserPoolAuthorizer` 支持）
- IaC：Chalice 自带部署（`chalice deploy`），底层生成 CloudFormation

### 方案 B：Node + Amplify Gen2

Amplify Gen2 是 AWS 的全栈开发框架，TypeScript-first，code-first 模型。

- 前端：React/Next.js SPA，Amplify Hosting 托管（S3 + CloudFront）
- 后端：Amplify 定义 Lambda Function，API Gateway 自动生成
- 认证：`defineAuth()` 原生集成 Cognito，Amplify UI 提供开箱即用的登录组件
- IaC：Amplify 底层使用 CDK，`amplify deploy` 一键部署

## 评估维度对比

| 维度 | Python + Chalice | Node + Amplify Gen2 |
|------|-----------------|-------------------|
| 开发复杂度 | 低。装饰器路由，代码量少，纯后端思维 | 中。需要学习 Amplify 约定、TypeScript 后端定义、React 前端 |
| 前端能力 | 弱。静态 HTML 需手写，无组件库支持 | 强。React 生态 + Amplify UI 组件（登录、表单等开箱即用） |
| Cognito 集成 | 简单。`CognitoUserPoolAuthorizer` 几行配置 | 极简。`defineAuth()` + `<Authenticator>` 组件，前后端一体 |
| 部署方式 | `chalice deploy` 一条命令 | `amplify deploy` 一条命令（含前端 + 后端 + CDN） |
| 冷启动 | Python Lambda 冷启动 ~300-800ms | Node Lambda 冷启动 ~200-500ms，略优 |
| 运行时成本 | 相同（都是 Lambda 按调用计费） | 相同 + CloudFront 少量费用（可忽略） |
| 维护成本 | 低。Chalice 成熟稳定，API 简洁 | 中。Amplify Gen2 较新，版本迭代快，breaking change 风险 |
| 已有 Cognito 集成 | 引用已有 User Pool ID 即可 | 需要配置 `referenceAuth()` 引用外部 Cognito 资源 |
| 团队技术栈匹配 | 适合 Python 团队 | 适合 TypeScript/React 团队 |

## 推荐方案：Python + Chalice

理由：

1. **项目定位是工具，不是产品**。Web UI 只需一个简单页面（显示 IP、状态、一个按钮），不需要 React 组件库和复杂前端框架。一个静态 HTML + 少量 JS 足矣。

2. **最小依赖原则**。Chalice 只引入一个框架依赖，部署产物就是 Lambda + API Gateway。Amplify Gen2 引入了 CDK、Amplify CLI、React、Node 构建链等一整套工具链，对于这个项目来说过重。

3. **Cognito 集成同样简单**。Chalice 原生支持 `CognitoUserPoolAuthorizer`，引用已有 User Pool 只需配置 Pool ID 和 App Client ID。前端用 Cognito Hosted UI 做登录跳转，无需引入 Amplify SDK。

4. **部署和维护更可控**。`chalice deploy` 生成的 CloudFormation 模板透明可审计。Amplify Gen2 的抽象层较厚，出问题时调试链路更长。

5. **Amplify Gen2 成熟度风险**。Gen2 仍在快速迭代中，API 变动频繁。Chalice 已经稳定多年，适合工具类项目的长期维护。

### 推荐架构概览

```
用户浏览器
  │
  ├─ 访问 Cognito Hosted UI 完成登录，获取 ID Token
  │
  ├─ 静态页面（S3 托管）
  │   ├─ JS 调用外部 API 获取当前 IP
  │   ├─ JS 调用后端 API 查询 IP 状态
  │   └─ JS 调用后端 API 更新白名单
  │
  └─ API Gateway（Cognito Authorizer）
      └─ Lambda（Chalice）
          ├─ GET  /status?ip=x.x.x.x  → 查询各 Region Prefix List
          └─ POST /update               → 更新各 Region Prefix List
              ├─ EC2 API (Region A) → Prefix List A → SG A1, A2...
              ├─ EC2 API (Region B) → Prefix List B → SG B1, B2...
              └─ EC2 API (Region N) → Prefix List N → SG N1, N2...
```
