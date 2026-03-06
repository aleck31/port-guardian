# EC2 SSH Guardian — 开发任务清单

## 1. 环境准备

- [ ] **T-1.1** 初始化项目结构
  - 创建目录：`chalice_app/`、`scripts/`
  - 创建 `requirements.txt`（chalice、boto3）
  - 创建配置模板 `config.yaml.example`（ACCOUNT_A、ACCOUNT_B、TARGET_ROLE_ARN、COGNITO_USER_POOL_ID、COGNITO_APP_CLIENT_ID、COGNITO_DOMAIN、TARGET_REGIONS、TARGET_TAG）
  - 验收：目录结构就绪，`pip install` 成功

- [ ] **T-1.2** 创建 Chalice app 骨架
  - `chalice_app/.chalice/config.json`（stage 配置、`autogen_policy: false`、环境变量）
  - `chalice_app/.chalice/policy-prod.json`（Lambda 执行角色自定义策略）
  - `chalice_app/app.py` 含 3 个空路由 + CognitoUserPoolAuthorizer 声明
  - 验收：`chalice local` 启动成功，3 个端点返回占位响应

## 2. 基础设施初始化脚本

- [ ] **T-2.1** `scripts/setup.py` — 配置加载
  - 读取 `config.yaml`，解析账号、region、tag 等配置
  - 验收：脚本能正确加载并打印配置

- [ ] **T-2.2** `scripts/setup.py` — 副账号 IAM Role 创建
  - 创建 `ssh-guardian-target-role`，Trust Policy 信任主账号 Lambda 角色
  - 附加最小权限策略（ec2:*PrefixList* + tag 条件）
  - 幂等：已存在则跳过
  - 验收：`aws iam get-role` 查到角色，Trust Policy 和权限正确

- [ ] **T-2.3** `scripts/setup.py` — 创建 Prefix List（所有账号所有 region）
  - 主账号 3 个 region：直接调用 EC2 API
  - 副账号 3 个 region：通过 AssumeRole 调用
  - MaxEntries=100，tag: ManagedBy=ssh-guardian
  - 幂等：按 tag 查询，已存在则跳过
  - 验收：6 个 region 均能查到 Prefix List

- [ ] **T-2.4** `scripts/setup.py` — 初始化 SG 入站规则
  - 按 target_tag 筛选各 region 的 Security Group
  - 为筛出的 SG 添加入站规则：TCP 22，source 为该 region 的 Prefix List
  - 幂等：已有该规则则跳过
  - 验收：目标 SG 入站规则引用 Prefix List

## 3. Lambda 业务逻辑

- [ ] **T-3.1** 公共模块 — EC2 client 工厂
  - `chalice_app/prefix_list_service.py`
  - 根据 account/region 返回 EC2 client：主账号直接创建，副账号通过 AssumeRole
  - 缓存 STS 临时凭证
  - 验收：单元测试通过

- [ ] **T-3.2** 公共模块 — Prefix List 操作
  - `get_prefix_list_id(ec2_client)` — 按 tag 查找 Prefix List ID
  - `check_ip_in_prefix_list(ec2_client, prefix_list_id, ip)` — 查询 IP 是否存在
  - `add_ip_to_prefix_list(ec2_client, prefix_list_id, ip)` — 追加 IP/32 条目
  - 验收：各函数 API 调用正确，处理 already_exists 场景

- [ ] **T-3.3** `GET /` 路由 — 返回 HTML
  - 读取 HTML 模板，注入 Cognito 配置和 API 端点 URL
  - 返回 Content-Type: text/html
  - 验收：访问 `/` 返回完整 HTML 页面

- [ ] **T-3.4** `GET /status` 路由
  - 从 `app.current_request.context` 提取 sourceIp
  - 遍历所有 target，调用 check_ip_in_prefix_list
  - 返回 `{ "current_ip": "...", "regions": [...] }`
  - 验收：返回格式符合 ARCH.md 定义

- [ ] **T-3.5** `POST /update` 路由
  - 从 sourceIp 提取 IP
  - 遍历所有 target，调用 add_ip_to_prefix_list
  - 返回各 region 操作结果
  - 验收：返回格式符合 ARCH.md 定义，Prefix List 条目实际增加

## 4. 前端 HTML 页面

- [ ] **T-4.1** HTML 页面 — 布局与样式
  - 单文件 HTML（内联 CSS + JS），响应式布局
  - 显示区域：当前 IP、各 Region 状态表格、更新按钮、操作结果
  - 验收：手机和桌面浏览器均正常显示

- [ ] **T-4.2** HTML 页面 — Cognito 登录集成
  - 检测 URL hash 中的 ID Token（Hosted UI 回调）
  - 未登录显示"登录"按钮，跳转 Cognito Hosted UI
  - 已登录后续 API 请求携带 Authorization header
  - 验收：登录流程完整

- [ ] **T-4.3** HTML 页面 — 状态查询与更新
  - 页面加载后自动调用 `GET /status`，显示 current_ip 和各 Region 状态
  - 点击"更新白名单"调用 `POST /update`，显示 loading
  - 更新完成后自动刷新状态
  - 验收：完整操作流程可在浏览器走通

## 5. 部署与测试

- [ ] **T-5.1** 基础设施初始化
  - 执行 `python scripts/setup.py`
  - 验收：6 个 Prefix List + SG 规则 + 副账号 Role 全部就绪

- [ ] **T-5.2** 应用部署
  - 执行 `cd chalice_app && chalice deploy --stage prod`
  - 验收：API Gateway URL 可访问，3 个路由正常

- [ ] **T-5.3** 端到端测试 — 登录 + 状态查询
  - 浏览器访问 → 登录 → 页面显示当前 IP 和 6 个 Region 状态
  - 验收：current_ip 正确，状态全部返回

- [ ] **T-5.4** 端到端测试 — IP 更新
  - 点击"更新白名单" → 所有 Region 返回 added/already_exists
  - 刷新状态 → 所有 Region 显示 in_prefix_list: true
  - 验收：Prefix List 条目增加，可 SSH 连接目标 EC2

- [ ] **T-5.5** 端到端测试 — 手机访问
  - 手机浏览器完成完整流程
  - 验收：响应式布局正常，操作流程完整
