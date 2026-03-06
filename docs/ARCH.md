# EC2 SSH Guardian — 架构设计文档

## 1. 整体架构

```
                          ┌─────────────────────────────────────────────┐
                          │            主账号 (Account A)                │
                          │            部署 Region (e.g. ap-east-1)     │
                          │                                             │
  ┌──────────┐  HTTPS     │  ┌──────────────┐    ┌──────────────────┐  │
  │  浏览器   │──────────►│  │ API Gateway   │───►│ Lambda (Chalice) │  │
  │ (手机/PC) │◄──────────│  │ + Cognito     │◄───│                  │  │
  └──────────┘  HTML/JSON │  │   Authorizer  │    │ - GET /  (HTML)  │  │
       │                  │  └──────────────┘    │ - GET /status    │  │
       │ Cognito          │                       │ - POST /update   │  │
       │ Hosted UI        │  ┌──────────────┐    └────────┬─────────┘  │
       └─────────────────►│  │ Cognito       │             │            │
                          │  │ User Pool     │             │            │
                          │  │ (已有)        │             │            │
                          │  └──────────────┘             │            │
                          └───────────────────────────────┼────────────┘
                                                          │
                    ┌─────────────────────────────────────┤
                    │ 运行时 STS AssumeRole               │
                    ▼                                     ▼
  ┌──────────────────────────────┐  ┌──────────────────────────────┐
  │  主账号 (Account A)           │  │  副账号 (Account B)           │
  │                              │  │                              │
  │  直接调用 EC2 API             │  │  AssumeRole ──► target-role  │
  │  (Lambda 执行角色自身权限)     │  │  (Trust: Account A Lambda)   │
  │                              │  │                              │
  │  Region1   Region2   Region3 │  │  Region1   Region2   Region3 │
  │ ┌───────┐ ┌───────┐ ┌─────┐ │  │ ┌───────┐ ┌───────┐ ┌─────┐ │
  │ │Prefix │ │Prefix │ │Pref.│ │  │ │Prefix │ │Prefix │ │Pref.│ │
  │ │List   │ │List   │ │List │ │  │ │List   │ │List   │ │List │ │
  │ └──┬────┘ └──┬────┘ └──┬──┘ │  │ └──┬────┘ └──┬────┘ └──┬──┘ │
  │ ┌──▼──┐   ┌──▼──┐  ┌──▼──┐ │  │ ┌──▼──┐   ┌──▼──┐  ┌──▼──┐ │
  │ │SG×N │   │SG×N │  │SG×N │ │  │ │SG×N │   │SG×N │  │SG×N │ │
  │ │:22  │   │:22  │  │:22  │ │  │ │:22  │   │:22  │  │:22  │ │
  │ └─────┘   └─────┘  └─────┘ │  │ └─────┘   └─────┘  └─────┘ │
  └──────────────────────────────┘  └──────────────────────────────┘
```

**关键设计决策：Lambda 只部署在主账号。跨账号访问是运行时行为，通过 STS AssumeRole 实现。**

**数据流：**

1. 用户浏览器 → Cognito Hosted UI → 获取 ID Token
2. 浏览器 → `GET /` → Lambda 返回 HTML 页面
3. 页面 JS → `GET /status` → Lambda 从 sourceIp 提取用户 IP，查询 6 个 Region 的 Prefix List → 返回 current_ip + 各 Region 状态
4. 用户点击按钮 → `POST /update` → Lambda 向 6 个 Region 的 Prefix List 追加 IP → 返回结果

**运行时调用链路：**

- 主账号 Region：Lambda 执行角色直接拥有 ec2:*PrefixList* 权限，直接调用 EC2 API
- 主账号其他 Region：同上，EC2 client 指定不同 region_name 即可
- 副账号所有 Region：Lambda → `sts:AssumeRole` → 副账号 `ssh-guardian-target-role` → 用临时凭证创建 EC2 client 调用

## 2. 组件职责

### 2.1 API Gateway

- 暴露 3 个端点：`GET /`、`GET /status`、`POST /update`
- `GET /` 不需要认证（返回登录页/静态 HTML）
- `GET /status` 和 `POST /update` 配置 Cognito Authorizer
- HTTPS 终端，提取 `sourceIp` 传递给 Lambda

### 2.2 Lambda (Chalice)

| 路由 | 职责 |
|------|------|
| `GET /` | 返回 HTML 页面（内嵌 Cognito 登录逻辑 + IP 显示 + 状态查询 + 更新按钮） |
| `GET /status` | 从 sourceIp 提取用户 IP，遍历 6 个 Region 的 Prefix List，查询该 IP 是否存在，返回 current_ip + 各 Region 状态 |
| `POST /update` | 从 API Gateway context 提取 `sourceIp`，遍历 6 个 Region，将 IP/32 追加到 Prefix List |

- 主账号 Region：直接使用 Lambda 执行角色调用 EC2 API
- 副账号 Region：通过 `sts:AssumeRole` 获取临时凭证，再调用副账号的 EC2 API

### 2.3 Cognito

- 使用用户已有的 User Pool，不新建
- 配置 App Client 用于 Web 登录（Hosted UI 或 SDK）
- API Gateway Cognito Authorizer 验证 ID Token

### 2.4 Managed Prefix List × 6

- 每个目标 Region 一个，共 6 个（2 账号 × 3 Region）
- 部署时创建，`MaxEntries` 初始设为 100（可 resize 至 1,000）
- 运行时只做追加，不删除条目
- 被该 Region 内多个 SG 引用

### 2.5 IAM 跨账号角色链路

```
Lambda 执行角色 (Account A)
  │
  ├─ 直接权限 ──► Account A 所有 target region 的 ec2:*PrefixList*
  │
  └─ sts:AssumeRole ──► Account B ssh-guardian-target-role
                         └─ ec2:*PrefixList* (Account B 所有 target region)
```

## 3. IAM 权限设计

### 3.1 Lambda 执行角色（主账号 Account A）

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "PrefixListOwnAccount",
      "Effect": "Allow",
      "Action": [
        "ec2:GetManagedPrefixListEntries",
        "ec2:ModifyManagedPrefixList",
        "ec2:DescribeManagedPrefixLists"
      ],
      "Resource": "arn:aws:ec2:*:<ACCOUNT_A>:prefix-list/pl-*",
      "Condition": {
        "StringEquals": {
          "ec2:ResourceTag/ManagedBy": "ssh-guardian"
        }
      }
    },
    {
      "Sid": "PrefixListDescribeOwnAccount",
      "Effect": "Allow",
      "Action": "ec2:DescribeManagedPrefixLists",
      "Resource": "*"
    },
    {
      "Sid": "AssumeTargetRole",
      "Effect": "Allow",
      "Action": "sts:AssumeRole",
      "Resource": "arn:aws:iam::<ACCOUNT_B>:role/ssh-guardian-target-role"
    },
    {
      "Sid": "CloudWatchLogs",
      "Effect": "Allow",
      "Action": [
        "logs:CreateLogGroup",
        "logs:CreateLogStream",
        "logs:PutLogEvents"
      ],
      "Resource": "arn:aws:logs:*:<ACCOUNT_A>:*"
    }
  ]
}
```

### 3.2 副账号 Target Role（Account B 预建）

角色名：`ssh-guardian-target-role`

信任策略（Trust Policy）：

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "AWS": "arn:aws:iam::<ACCOUNT_A>:role/ssh-guardian-lambda-role"
      },
      "Action": "sts:AssumeRole"
    }
  ]
}
```

权限策略（最小权限，覆盖该账号所有 target region）：

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "PrefixListReadWrite",
      "Effect": "Allow",
      "Action": [
        "ec2:GetManagedPrefixListEntries",
        "ec2:ModifyManagedPrefixList",
        "ec2:DescribeManagedPrefixLists"
      ],
      "Resource": "arn:aws:ec2:*:<ACCOUNT_B>:prefix-list/pl-*",
      "Condition": {
        "StringEquals": {
          "ec2:ResourceTag/ManagedBy": "ssh-guardian"
        }
      }
    },
    {
      "Sid": "PrefixListDescribe",
      "Effect": "Allow",
      "Action": "ec2:DescribeManagedPrefixLists",
      "Resource": "*"
    }
  ]
}
```

### 3.3 前置条件

- 副账号的 `ssh-guardian-target-role` 通过 `scripts/setup.py` 自动创建
- 该角色是 Chalice 部署的前置依赖，需先执行 setup 脚本

### 3.4 部署时额外权限（仅 setup.py 使用，不给 Lambda 运行时）

```
ec2:CreateManagedPrefixList
ec2:CreateTags
ec2:DescribeSecurityGroups
ec2:AuthorizeSecurityGroupIngress
```

## 4. API 接口定义

### GET /

返回 HTML 页面，无需认证。

```
Response: Content-Type: text/html
```

页面包含：Cognito 登录跳转、IP 显示、状态面板、更新按钮。

### GET /status

查询当前用户 IP 是否在各 Region 的 Prefix List 中。需要 Cognito 认证。IP 从 API Gateway `requestContext.identity.sourceIp` 提取，无需前端传参。

```
Request:
  (无参数，IP 从 API Gateway sourceIp 自动提取)

Response: 200
{
  "current_ip": "203.0.113.50",
  "regions": [
    { "account": "111111111111", "region": "ap-east-1",      "in_prefix_list": true  },
    { "account": "111111111111", "region": "ap-southeast-1", "in_prefix_list": false },
    { "account": "111111111111", "region": "us-west-2",      "in_prefix_list": false },
    { "account": "222222222222", "region": "ap-east-1",      "in_prefix_list": true  },
    { "account": "222222222222", "region": "ap-southeast-1", "in_prefix_list": false },
    { "account": "222222222222", "region": "us-west-2",      "in_prefix_list": false }
  ]
}
```

### POST /update

将请求来源 IP 追加到所有目标 Region 的 Prefix List。需要 Cognito 认证。

```
Request:
  Body: (空，IP 从 API Gateway requestContext.identity.sourceIp 提取)

Response: 200
{
  "ip": "203.0.113.50",
  "results": [
    { "account": "111111111111", "region": "ap-east-1",      "status": "added" },
    { "account": "111111111111", "region": "ap-southeast-1", "status": "added" },
    { "account": "111111111111", "region": "us-west-2",      "status": "added" },
    { "account": "222222222222", "region": "ap-east-1",      "status": "added" },
    { "account": "222222222222", "region": "ap-southeast-1", "status": "already_exists" },
    { "account": "222222222222", "region": "us-west-2",      "status": "added" }
  ]
}

Response: 401
{ "message": "Unauthorized" }
```

## 5. 部署架构

### 5.1 工具分工

| 工具 | 职责 |
|------|------|
| `chalice deploy` | 部署 Lambda + API Gateway + Cognito Authorizer + Lambda 执行角色（主账号部署 Region） |
| `scripts/setup.py` | 基础设施初始化（boto3）：两个账号的 Prefix List 创建、SG 规则添加、副账号 IAM Role 创建 |

Chalice 原生支持 `CognitoUserPoolAuthorizer`，在 `app.py` 中声明即可，`chalice deploy` 自动配置 API Gateway Authorizer。不需要 CDK。

### 5.2 Chalice 部署

Chalice 自动管理：
- Lambda 函数（Python runtime）
- API Gateway REST API（3 个路由）
- Cognito User Pool Authorizer（引用已有 User Pool）
- Lambda 执行角色（通过 `.chalice/config.json` 中 `autogen_policy: false` + 自定义 policy）

```bash
# 部署应用
cd chalice_app && chalice deploy --stage prod
```

### 5.3 setup.py 初始化流程

```bash
# 初始化所有基础设施（主账号 + 副账号）
python scripts/setup.py
```

脚本按顺序执行：

1. 副账号：创建 `ssh-guardian-target-role`（Trust 主账号 Lambda 角色）
2. 主账号各 target region：创建 Prefix List（tag: ManagedBy=ssh-guardian）
3. 副账号各 target region：创建 Prefix List（通过 AssumeRole）
4. 所有 target region：按 `target_tag` 筛选 SG，添加 Prefix List 入站规则（TCP 22）

所有操作幂等，重复执行安全。

### 5.4 部署顺序

```
1. python scripts/setup.py          # 基础设施初始化
2. cd chalice_app && chalice deploy  # 应用部署
```

### 5.5 资源归属总结

| 资源 | 归属 | 部署方式 | 数量 |
|------|------|---------|------|
| API Gateway + Lambda | Account A / 部署 Region | chalice deploy | 1 |
| Lambda 执行角色 | Account A / 部署 Region | chalice deploy | 1 |
| Cognito Authorizer | Account A / 部署 Region | chalice deploy | 1 |
| Target Role (Account B) | Account B / Global (IAM) | scripts/setup.py | 1 |
| Prefix List (Account A) | Account A / 各 target Region | scripts/setup.py | 3 |
| Prefix List (Account B) | Account B / 各 target Region | scripts/setup.py | 3 |
| SG 入站规则 (Account A) | Account A / 各 target Region | scripts/setup.py | N |
| SG 入站规则 (Account B) | Account B / 各 target Region | scripts/setup.py | N |
| Cognito User Pool | 已有 | 不创建 | 0 |
