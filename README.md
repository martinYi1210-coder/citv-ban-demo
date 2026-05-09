# CITV Callback V2 双向签名回调测试工具

根据 [citv-callback-v2 官方文档](https://eh.citv.cc/docs/docs/citv-callback-v2) 实现的完整测试工具，演示了调用方与被调用方之间的双向RSA签名验证流程。

---

## 整体流程说明

```
┌─────────────┐                                  ┌─────────────┐
│  调用方     │                                  │  被调用方   │
│   (CITV)    │                                  │ (SaaS平台)  │
└──────┬──────┘                                  └──────┬──────┘
       │                                                │
       │ 1. 准备请求参数：                               │
       │    - ccid, casn, action, code, message         │
       │                                                │
       │ 2. 生成请求头：                                 │
       │    - timestamp: 13位Unix时间戳                 │
       │    - nonce: 随机字符串(防重放)                 │
       │    - appid: 应用唯一标识                       │
       │                                                │
       │ 3. 使用【CITV私钥】生成请求签名                │
       │    签名范围: appid + casn + ccid + nonce + timestamp │
       │    算法: SHA256withRSA → Base64编码           │
       │                                                │
       │─────────────── POST /ban/v2 ─────────────────►│
       │   请求头: sign, timestamp, nonce, appid        │
       │   请求体: {ccid, casn, action, code, message}  │
       │                                                │
       │                                                │ 4. 验证请求签名
       │                                                │    使用【CITV公钥】验证
       │                                                │
       │                                                │ 5. 验证时间戳(有效期5分钟)
       │                                                │
       │                                                │ 6. 验证nonce唯一性
       │                                                │
       │                                                │ 7. 执行业务逻辑(封禁/整改/解封)
       │                                                │
       │                                                │ 8. 生成响应
       │                                                │    ticketId, ccid, nonce, timestamp
       │                                                │
       │                                                │ 9. 使用【SaaS私钥】生成响应签名
       │                                                │    签名范围: ccid + nonce + ticketId + timestamp
       │                                                │
       │◄──────────────── 返回响应 ─────────────────────│
       │    {ticketId, ccid, nonce, timestamp, sign}    │
       │                                                │
       │ 10. 使用【SaaS公钥】验证响应签名               │
       │                                                │
       │ 11. 完成！                                     │
```

---

## 目录结构

```
citv-ban-test/
├── keys/                      # RSA密钥对目录
│   ├── generate_keys.go       # 密钥生成工具
│   ├── citv_private.pem       # CITV私钥 【调用方持有，用于签名请求】
│   ├── citv_public.pem        # CITV公钥  【被调用方持有，用于验签请求】
│   ├── saas_private.pem       # SaaS私钥  【被调用方持有，用于签名响应】
│   └── saas_public.pem        # SaaS公钥  【调用方持有，用于验签响应】
│
├── callee/                    # 被调用方（SaaS平台服务）
│   ├── main.go                # 接口实现
│   ├── go.mod
│   └── callee                 # 可执行文件
│
└── caller/                    # 调用方（CITV客户端）
    ├── main.go                # 请求发送实现
    ├── go.mod
    └── caller                 # 可执行文件
```

### 密钥交换说明

> **重要**：实际部署时，双方**只交换公钥**，私钥必须严格保密，绝不能泄露给对方。

| 密钥 | 持有者 | 用途 |
|------|--------|------|
| CITV私钥 | 仅调用方(CITV)持有 | 对发出的封禁请求进行签名 |
| CITV公钥 | 公开给被调用方 | 被调用方用来验证请求确实来自CITV |
| SaaS私钥 | 仅被调用方(SaaS)持有 | 对返回的响应进行签名 |
| SaaS公钥 | 公开给调用方 | 调用方用来验证响应确实来自SaaS平台 |

---

## 快速开始

### 第一步：启动被调用方（SaaS平台服务）

在第一个终端窗口运行：

```bash
cd callee
go run main.go
```

成功启动后会显示：
```
被调用方(SaaS平台)启动成功
监听端口: 8081
接口路径: /ban/v2
```

### 第二步：运行调用方测试

在第二个终端窗口运行：

```bash
cd caller
go run main.go
```

调用方会依次发送3个测试用例，每个用例都会完整演示签名→请求→验签→响应→验证响应签名的全流程。

---

## 接口详细规范

### 请求信息

| 项 | 值 |
|----|----|
| 请求方式 | POST |
| 接口路径 | `/ban/v2` |
| Content-Type | `application/json` |

### 请求头参数

| 参数名 | 类型 | 必填 | 说明 |
|--------|------|------|------|
| sign | string | 是 | RSA签名结果，Base64编码 |
| timestamp | string | 是 | Unix时间戳，13位毫秒级 |
| nonce | string | 是 | 随机字符串，防止重放攻击 |
| appid | string | 是 | 应用唯一标识 |

### 请求体参数

| 参数名 | 类型 | 必填 | 说明 |
|--------|------|------|------|
| ccid | string | 是 | 封禁专用全局唯一ID |
| casn | string | 是 | CITV内部审核单号 |
| action | int | 是 | 操作类型（见下文说明） |
| code | int | 是 | 处置代码（见下文说明） |
| message | string | 否 | CITV通知文本 |

### 响应参数

| 参数名 | 类型 | 说明 |
|--------|------|------|
| ticketId | string | 处理追踪编号 |
| ccid | string | 回传封禁专用ID |
| nonce | string | 响应随机串 |
| timestamp | number | Unix时间戳（13位） |
| sign | string | 响应签名 |

---

## 签名算法详解

### 签名生成步骤

1. **收集签名字段**：取出所有需要签名的参数
2. **按字母排序**：将参数名按ASCII码从小到大排序
3. **拼接字符串**：`key1=value1&key2=value2&key3=value3...` 格式拼接
4. **SHA256摘要**：对拼接后的字符串计算SHA256哈希
5. **RSA签名**：使用私钥对哈希值进行RSA签名
6. **Base64编码**：将签名结果进行Base64编码，得到最终的sign值

### 请求签名范围（调用方 → 被调用方）

按字母序拼接以下5个字段：
```
appid={appid}&casn={casn}&ccid={ccid}&nonce={nonce}&timestamp={timestamp}
```

### 响应签名范围（被调用方 → 调用方）

按字母序拼接以下4个字段：
```
ccid={ccid}&nonce={nonce}&ticketId={ticketId}&timestamp={timestamp}
```

---

## 操作类型（action）说明

| 值 | 含义 |
|----|------|
| -1 | 立即封禁 |
| 1~24 | 限期整改（小时数） |
| 127 | 解封 |

## 处置代码（code）说明

| 值 | 含义 |
|----|------|
| 0 | 测试 |
| 1 | 涉黄 |
| 2 | 涉暴 |
| 3 | 涉政 |
| 4 | 监管要求 |
| 5 | 协同要求 |
| 10 | 版权 |
| 11 | 诱导打赏 |
| 12 | 夸大宣传 |
| 13 | 涉老欺诈 |
| 14 | 诈骗 |
| 15 | 投诉高发 |
| 100 | 重点防范 |

---

## 错误处理

鉴权失败时返回统一错误格式：

```json
{
  "isok": false,
  "msg": "错误描述",
  "code": 错误码,
  "dataObj": null
}
```

### 错误码说明

| 错误码 | 含义 |
|--------|------|
| -100 | 签名为空 |
| -101 | 时间戳为空 |
| -102 | AppId为空 |
| -103 | 签名验证失败 / 时间戳过期 / nonce重复 |
| -104 | AppId非法 |

---

## 安全机制

1. **双向签名**：请求和响应都需要签名，确保双方身份可信
2. **时间戳校验**：时间戳有效期5分钟，防止过时的重放攻击
3. **Nonce防重放**：每个nonce只能使用一次，防止同一请求被重复提交
4. **RSA 4096位**：使用高强度密钥，确保签名不可伪造

---

## 自定义测试

如需测试自己的业务场景，可以修改 `caller/main.go` 中的 `testCases` 数组，添加自定义的测试用例。
