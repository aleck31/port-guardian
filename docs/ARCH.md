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

- 副账号的 `ssh-guardian-target-role` 由用户手动创建，或通过独立 CDK stack / CloudFormation 模板部署
- 该角色是 CDK 主部署的前置依赖，不在主 CDK app 中管理

### 3.4 部署时额外权限（仅初始化脚本使用，不给 Lambda 运行时）

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

## 5. 部署工具评估

| 维度 | CDK (Python) | SAM | Terraform |
|------|-------------|-----|-----------|
| 语言 | Python（与 Chalice Lambda 一致） | YAML 模板 + Python Lambda | HCL + Python Lambda |
| 跨 Region 部署 | 原生支持（多 Stack 指定 env） | 需多次 deploy 指定 region | 原生支持（provider alias） |
| Cognito 集成 | L2 Construct 完善 | 支持但配置冗长 | 支持 |
| Prefix List 资源 | `CfnPrefixList` 可用 | CloudFormation 原生支持 | `aws_ec2_managed_prefix_list` |
| 学习曲线 | 低（用户已倾向 CDK Python） | 中 | 中（需学 HCL） |
| 与 Chalice 集成 | 可通过 CDK Stack 编排 Chalice 部署 | Chalice 独立部署 | Chalice 独立部署 |

**结论：CDK Python。**

理由：用户倾向 CDK Python；与 Lambda 代码同语言；Prefix List、IAM Role 均有成熟 Construct；Chalice 负责 Lambda + API Gateway 部署，CDK 负责 Prefix List 等基础设施。

## 6. 部署架构

### 6.1 CDK Stack 结构

```
cdk_app (仅部署到主账号 Account A)
│
├── MainStack (Account A / 部署 Region)
│   ├── Chalice 应用部署（API Gateway + Lambda）
│   ├── Lambda 执行角色（ec2:*PrefixList* + sts:AssumeRole）
│   └── Cognito App Client 配置（引用已有 User Pool）
│
├── PrefixListStack-Region1 (Account A / Region 1)
│   ├── Managed Prefix List (tag: ManagedBy=ssh-guardian)
│   └── SG 入站规则初始化（按 target_tag 筛选 SG，添加 Prefix List 引用）
│
├── PrefixListStack-Region2 (Account A / Region 2)
└── PrefixListStack-Region3 (Account A / Region 3)
```

共 1 个 MainStack + 3 个 PrefixListStack（主账号 3 个 Region）。

副账号的 Prefix List 和 SG 规则通过独立脚本或 CDK app 部署（使用副账号凭证）。

### 6.2 副账号前置条件（独立于主 CDK app）

用户需在副账号预先完成：

1. 创建 `ssh-guardian-target-role`（Trust 主账号 Lambda 角色）
2. 在各 target region 创建 Prefix List（可提供独立 CDK stack 或脚本）
3. 按 `target_tag` 为目标 SG 添加 Prefix List 入站规则

可提供 `scripts/setup_target_account.py` 脚本自动化以上步骤。

### 6.3 Bootstrap（仅主账号）

```bash
# Bootstrap 主账号部署 Region
cdk bootstrap aws://<ACCOUNT_A>/<DEPLOY_REGION>

# Bootstrap 主账号其他 target Region（跨 Region 部署 PrefixListStack）
cdk bootstrap aws://<ACCOUNT_A>/<REGION_2>
cdk bootstrap aws://<ACCOUNT_A>/<REGION_3>
```

副账号不需要 CDK bootstrap，其资源通过独立脚本或 CloudFormation 模板管理。

### 6.4 部署命令

```bash
# 部署主账号所有 Stack（MainStack + PrefixListStack × 3）
cdk deploy --all

# 初始化副账号（独立脚本，使用副账号凭证）
python scripts/setup_target_account.py --account <ACCOUNT_B> --regions region1,region2,region3
```

### 6.5 资源归属总结

| 资源 | 归属 | 部署方式 | 数量 |
|------|------|---------|------|
| API Gateway + Lambda | Account A / 部署 Region | CDK MainStack | 1 |
| Lambda 执行角色 | Account A / 部署 Region | CDK MainStack | 1 |
| Prefix List (Account A) | Account A / 各 target Region | CDK PrefixListStack | 3 |
| SG 入站规则 (Account A) | Account A / 各 target Region | CDK PrefixListStack | N |
| Target Role (Account B) | Account B / Global (IAM) | 手动或独立脚本 | 1 |
| Prefix List (Account B) | Account B / 各 target Region | 独立脚本 | 3 |
| SG 入站规则 (Account B) | Account B / 各 target Region | 独立脚本 | N |
| Cognito User Pool | 已有 | 不创建 | 0 |
