# EC2 SSH Guardian — 需求规格说明书

## 1. 项目概述

EC2 SSH Guardian 是一个轻量级的 SSH 访问控制工具，解决多 AWS 账号、多 Region 环境下 EC2 实例 22 端口安全暴露的问题。

**核心痛点：**
- 22 端口开放公网存在安全风险
- 用户 IP 频繁变化（大陆/香港切换、不同运营商），无法维护固定白名单
- 多 Region、多 Security Group 手动维护繁琐且易出错

**解决思路：**

用户通过 Web 页面登录（Cognito 认证），查看当前 IP 及 SSH 访问状态，一键触发 Lambda 将当前 IP 更新到对应 Region 的 AWS Managed Prefix List。多个 Security Group 引用同一个 Prefix List，实现一次更新、全部同步。22 端口仅对 Prefix List 中的 IP 开放，对公网关闭。

## 2. 功能需求

### 2.1 Web UI

- Lambda 直接返回 HTML 页面（无 S3 托管，通过 API Gateway 提供）
- 页面打开后通过 JS 调用外部 IP 检测 API，自动显示用户当前公网 IP
- 调用后端 API 检测当前 IP 是否已在 Prefix List 中，显示 SSH 访问状态（可访问 / 不可访问）
- 提供"更新白名单"按钮，点击后触发 Lambda 将当前 IP 加入 Prefix List
- 操作完成后自动刷新访问状态，告知用户已打通

### 2.2 认证

- 集成用户已有的 Cognito User Pool
- Web 页面通过 Cognito Hosted UI 或 SDK 完成登录
- API Gateway 使用 Cognito Authorizer 验证请求

### 2.3 IP 更新接口

- 提供 HTTPS API 端点（通过 API Gateway 暴露）
- 接收前端传入的用户公网 IP（IPv4）
- 调用 Lambda 将 IP 更新到目标 Region 的 Managed Prefix List
- 返回更新结果（成功/失败、当前 IP、更新的 Region 列表）

### 2.4 IP 状态查询接口

- 提供 HTTPS API 端点，接收用户公网 IP，查询该 IP 是否存在于各 Region 的 Prefix List 中
- 返回各 Region 的匹配状态

### 2.5 Prefix List 管理

- 每个目标 Region 维护一个 Managed Prefix List
- 采用追加模式：每次用户 IP 变化时，将新 IP（`/32` CIDR）作为新条目加入 Prefix List，不删除旧条目
- Prefix List 条目天然构成 IP 访问历史记录，无需额外数据库
- 支持配置多个目标 Region

### 2.6 Security Group 集成

- 各 Region 的 Security Group 通过引用 Prefix List 控制 22 端口入站规则
- Prefix List 更新后，所有引用它的 Security Group 自动生效，无需额外操作

### 2.7 配置方式

- 部署时固化为 Lambda 环境变量（不可运行时修改）：
  - AWS 账号 ID
  - 跨账号 AssumeRole ARN
  - Cognito User Pool ID / App Client ID
- 运行时可配置参数（通过 API 或环境变量传入）：
  - `target_regions`：目标 Region 列表
  - `target_tag`：用于筛选目标 Security Group 的 Tag 键值对

### 2.8 部署时初始化

- 在各 `target_regions` 中创建 Managed Prefix List
- 按 `target_tag` 筛选目标 Security Group
- 自动为筛出的 SG 添加引用 Prefix List 的入站规则（TCP port 22）
- 运行时 Lambda 只负责往 Prefix List 追加 IP，不再修改 SG

### 2.9 多设备支持

- 支持手机、电脑等任意设备通过浏览器触发 IP 更新
- 无需安装客户端，一键操作

## 3. 非功能需求

| 维度 | 要求 |
|------|------|
| 安全性 | Cognito 认证；HTTPS 传输；最小权限 IAM 策略 |
| 延迟 | IP 更新请求端到端响应 < 10 秒 |
| 可用性 | 依赖 AWS 托管服务（API Gateway、Lambda），无需自建服务器 |
| 成本 | Serverless 架构，按调用量计费，闲时零成本 |
| 可维护性 | 基础设施即代码（IaC），支持一键部署和更新 |
| 可观测性 | Lambda 日志输出到 CloudWatch，便于排查问题 |

## 4. 用户故事

| # | 用户故事 | 验收标准 |
|---|---------|---------|
| US-1 | 作为运维人员，我希望打开 Web 页面就能看到我的当前 IP 和 SSH 访问状态，这样我能快速判断是否需要更新白名单 | 页面加载后自动显示当前公网 IP 及各 Region 的访问状态（可访问/不可访问） |
| US-2 | 作为运维人员，我希望点击一个按钮就能将当前 IP 同步更新到所有 Region 的白名单 | 点击"更新白名单"后，所有已配置 Region 的 Prefix List 更新完成，页面刷新状态为"可访问" |
| US-3 | 作为运维人员，我希望在手机上也能登录并触发 IP 更新，这样出门在外也能紧急处理服务器问题 | 手机浏览器可正常完成 Cognito 登录并触发更新 |
| US-4 | 作为安全负责人，我希望 API 端点通过 Cognito 认证保护，防止未授权用户篡改白名单 | 未登录或 Token 过期的请求返回 401，不执行任何更新 |
| US-5 | 作为运维人员，我希望 22 端口只对白名单 IP 开放，不暴露在公网 | Security Group 入站规则仅引用 Prefix List，无 0.0.0.0/0 规则 |

## 5. 范围边界

### 在范围内（In Scope）

- API Gateway + Lambda 后端 API（含直接返回 HTML 页面，无 S3 托管）
- Cognito 认证集成（使用已有 User Pool）
- Web 页面（IP 显示、状态查询、一键更新）
- 来源 IP 提取与 Managed Prefix List 更新
- 多 Region Prefix List 同步（2 个 AWS 账号 × 3 个 Region = 6 个目标 Region）
- 部署时初始化：创建 Prefix List、按 Tag 筛选 SG、自动添加入站规则
- 基础设施即代码（CDK / CloudFormation / Terraform）
- CloudWatch 日志

### 不在范围内（Out of Scope）

- 用户管理系统 / 多用户权限体系（使用已有 Cognito User Pool，不新建）
- 自动过期清理旧 IP
- IPv6 支持
- 非 SSH（非 22 端口）的访问控制

## 6. 约束条件

| 约束 | 说明 |
|------|------|
| AWS Managed Prefix List 条目上限 | 单个 Prefix List 最大条目数为 1,000（默认值在创建时指定，可通过 resize 扩展至 1,000 上限）。采用追加模式后需关注条目增长，接近上限时需人工清理旧条目或提交 AWS Support Case 申请提升配额 |
| 跨 Region 调用延迟 | Lambda 需跨 2 个账号、共 6 个 Region 调用 EC2 API 更新 Prefix List，存在网络延迟 |
| API Gateway 部署区域 | Webhook 端点部署在单一 Region，用户从不同地理位置访问延迟不同 |
| Token 管理 | 依赖 Cognito 管理认证令牌，Token 自动刷新与过期由 Cognito SDK 处理 |
| IAM 权限 | Lambda 执行角色需要跨账号 AssumeRole 权限，目标角色需具备 `ec2:ModifyManagedPrefixList`、`ec2:GetManagedPrefixListEntries`、`ec2:DescribeSecurityGroups`、`ec2:AuthorizeSecurityGroupIngress` 等权限 |
| Prefix List 引用前置条件 | 部署时自动按 `target_tag` 筛选 SG 并添加 Prefix List 入站规则，运行时不再修改 SG |
| 目标环境规模 | 2 个 AWS 账号，每账号 3 个 Region，共 6 个目标 Region |
