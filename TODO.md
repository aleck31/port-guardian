# EC2 SSH Guardian — 开发任务清单

## 1. 环境准备

- [ ] **T-1.1** 初始化 Python 项目结构
  - 创建 `pyproject.toml` 或 `requirements.txt`，依赖：`aws-cdk-lib`、`chalice`、`boto3`
  - 创建目录结构：`cdk/`、`chalice_app/`、`scripts/`
  - 验收：`pip install` 成功，目录结构就绪

- [ ] **T-1.2** 创建 CDK app 骨架
  - `cdk/app.py` 入口，`cdk/cdk.json` 配置
  - 空的 `MainStack` 和 `PrefixListStack` 类
  - 验收：`cdk synth` 无报错，输出空模板

- [ ] **T-1.3** 创建 Chalice app 骨架
  - `chalice_app/.chalice/config.json` 配置
  - `chalice_app/app.py` 含 3 个空路由
  - 验收：`chalice local` 启动成功，3 个端点返回占位响应

- [ ] **T-1.4** 创建配置文件
  - `config.yaml` 或环境变量模板（`.env.example`），包含：ACCOUNT_A、ACCOUNT_B、TARGET_ROLE_ARN、COGNITO_USER_POOL_ID、COGNITO_APP_CLIENT_ID、TARGET_REGIONS、TARGET_TAG
  - 验收：配置项完整，有注释说明

## 2. 副账号初始化脚本

- [ ] **T-2.1** `scripts/setup_target_account.py` — 创建 IAM Role
  - 接收参数：`--account-id`、`--lambda-role-arn`（主账号 Lambda 角色 ARN）
  - 创建 `ssh-guardian-target-role`，Trust Policy 信任主账号 Lambda 角色
  - 附加最小权限策略（ec2:*PrefixList* + tag 条件）
  - 验收：脚本执行后，`aws iam get-role` 能查到角色，Trust Policy 正确

- [ ] **T-2.2** `scripts/setup_target_account.py` — 创建 Prefix List
  - 接收参数：`--regions`（逗号分隔的 region 列表）
  - 在每个 target region 创建 Managed Prefix List（MaxEntries=100，tag: ManagedBy=ssh-guardian）
  - 幂等：已存在则跳过
  - 验收：各 region `aws ec2 describe-managed-prefix-lists` 能查到，tag 正确

- [ ] **T-2.3** `scripts/setup_target_account.py` — 初始化 SG 入站规则
  - 接收参数：`--target-tag`（key=value 格式）
  - 按 tag 筛选各 region 的 Security Group
  - 为筛出的 SG 添加入站规则：TCP 22，source 为该 region 的 Prefix List
  - 幂等：已有该规则则跳过
  - 验收：`aws ec2 describe-security-groups` 显示入站规则引用 Prefix List

## 3. CDK Stack 开发

- [ ] **T-3.1** `MainStack` — Lambda 执行角色
  - 创建 IAM Role，权限：主账号 ec2:*PrefixList*（tag 条件）+ sts:AssumeRole（副账号 Role ARN）+ CloudWatch Logs
  - 验收：`cdk synth` 输出的 IAM Policy 符合 ARCH.md 3.1 节定义

- [ ] **T-3.2** `MainStack` — Chalice 部署集成
  - CDK 中集成 Chalice 部署（通过 subprocess 调用 `chalice package` 或使用 cdk-chalice construct）
  - Lambda 环境变量注入：ACCOUNT_A、ACCOUNT_B、TARGET_ROLE_ARN、COGNITO 配置、TARGET_REGIONS、TARGET_TAG
  - 验收：`cdk deploy MainStack` 成功，Lambda 函数创建，环境变量正确

- [ ] **T-3.3** `MainStack` — API Gateway + Cognito Authorizer
  - REST API 配置 3 个路由
  - Cognito Authorizer 引用已有 User Pool，保护 `/status` 和 `/update`
  - 验收：API Gateway 控制台可见 3 个路由，Authorizer 配置正确

- [ ] **T-3.4** `PrefixListStack` — 主账号 Prefix List 创建
  - 参数化 Stack：接收 region、target_tag
  - 创建 Managed Prefix List（MaxEntries=100，tag: ManagedBy=ssh-guardian）
  - 验收：`cdk deploy PrefixListStack-*` 成功，各 region Prefix List 创建

- [ ] **T-3.5** `PrefixListStack` — 主账号 SG 入站规则
  - 使用 Custom Resource (Lambda) 按 target_tag 筛选 SG，添加 Prefix List 入站规则
  - 幂等处理
  - 验收：目标 SG 入站规则包含 Prefix List 引用，TCP 22

## 4. Lambda 业务逻辑

- [ ] **T-4.1** 公共模块 — EC2 client 工厂
  - `chalice_app/prefix_list_service.py`
  - 根据 account/region 返回 EC2 client：主账号直接创建，副账号通过 AssumeRole 创建
  - 缓存 STS 临时凭证（避免重复 AssumeRole）
  - 验收：单元测试通过，主账号/副账号分别返回正确 client

- [ ] **T-4.2** 公共模块 — Prefix List 操作
  - `chalice_app/prefix_list_service.py`
  - `get_prefix_list_id(ec2_client)` — 按 tag ManagedBy=ssh-guardian 查找 Prefix List ID
  - `check_ip_in_prefix_list(ec2_client, prefix_list_id, ip)` — 查询 IP 是否存在
  - `add_ip_to_prefix_list(ec2_client, prefix_list_id, ip)` — 追加 IP/32 条目
  - 验收：各函数对 boto3 API 调用正确，处理 already_exists 场景

- [ ] **T-4.3** `GET /` 路由 — 返回 HTML
  - 读取 HTML 模板，注入 Cognito 配置（User Pool ID、App Client ID、Hosted UI URL）和 API 端点 URL
  - 返回 Content-Type: text/html
  - 验收：`chalice local` 访问 `/` 返回完整 HTML 页面

- [ ] **T-4.4** `GET /status` 路由
  - 从 `app.current_request.context` 提取 sourceIp
  - 遍历所有 target（account + region），调用 check_ip_in_prefix_list
  - 返回 `{ "current_ip": "...", "regions": [...] }`
  - 验收：返回格式符合 ARCH.md 4 节定义，current_ip 正确

- [ ] **T-4.5** `POST /update` 路由
  - 从 sourceIp 提取 IP
  - 遍历所有 target，调用 add_ip_to_prefix_list
  - 返回各 region 的操作结果（added / already_exists / error）
  - 验收：返回格式符合 ARCH.md 4 节定义，Prefix List 条目实际增加

## 5. 前端 HTML 页面

- [ ] **T-5.1** HTML 页面 — 布局与样式
  - 单文件 HTML（内联 CSS + JS），响应式布局，适配手机和桌面
  - 显示区域：当前 IP、各 Region 状态表格、更新按钮、操作结果
  - 验收：手机和桌面浏览器均可正常显示

- [ ] **T-5.2** HTML 页面 — Cognito 登录集成
  - 检测 URL hash 中的 ID Token（Hosted UI 回调）
  - 未登录时显示"登录"按钮，跳转 Cognito Hosted UI
  - 已登录时显示用户信息，后续 API 请求携带 Authorization header
  - 验收：登录流程完整，Token 过期时重新跳转登录

- [ ] **T-5.3** HTML 页面 — 状态查询与更新
  - 页面加载后自动调用 `GET /status`，显示 current_ip 和各 Region 状态
  - 点击"更新白名单"按钮调用 `POST /update`，显示 loading 状态
  - 更新完成后自动刷新状态
  - 验收：完整操作流程可在浏览器中走通

## 6. 部署与测试

- [ ] **T-6.1** 端到端部署 — 主账号
  - `cdk deploy --all` 部署 MainStack + PrefixListStack
  - 验收：所有 Stack 部署成功，API Gateway URL 可访问

- [ ] **T-6.2** 端到端部署 — 副账号初始化
  - 执行 `scripts/setup_target_account.py`
  - 验收：副账号 IAM Role、Prefix List、SG 规则全部就绪

- [ ] **T-6.3** 端到端测试 — 登录 + 状态查询
  - 浏览器访问 API Gateway URL → 登录 → 页面显示当前 IP 和各 Region 状态
  - 验收：6 个 Region 状态全部返回，current_ip 显示正确

- [ ] **T-6.4** 端到端测试 — IP 更新
  - 点击"更新白名单" → 所有 Region 返回 added/already_exists
  - 刷新状态 → 所有 Region 显示 in_prefix_list: true
  - 验收：Prefix List 条目实际增加，SG 生效后可 SSH 连接目标 EC2

- [ ] **T-6.5** 端到端测试 — 手机访问
  - 手机浏览器完成完整流程：登录 → 查看状态 → 更新白名单
  - 验收：页面响应式布局正常，操作流程完整
