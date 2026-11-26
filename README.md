# melo/jwt

基于 `firebase/php-jwt` 的 JWT 认证包，专为 Webman / Workerman 设计，也可在任意 PHP 项目中独立使用。

- 多守卫（多套密钥 / 算法 / 有效期）
- HMAC（HS256/384/512）与非对称（RS/ES/EdDSA）算法
- **统一签发**：`encode()` 一次返回 access + refresh 双令牌，access / refresh 使用**独立密钥**
- 单点登录（Redis / MySQL ThinkORM）：同用户同设备只保留一个有效会话，登出只需用户ID
- refresh 可轮换、类型声明防滥用
- Webman 认证中间件（仅请求头取 token）+ 统一 401 响应
- 静态门面与**大驼峰**全局辅助函数

## 安装

```bash
composer require melo/jwt
```

## 配置

把包内的配置模板复制到 Webman 应用的 `config/` 目录：

```bash
cp vendor/melo/jwt/config/melo-jwt.php config/melo-jwt.php
```

然后按需修改 `config/melo-jwt.php`，重点是 `guards.default.secret`、`guards.default.refresh_secret`（换成随机强密钥）、`ttl`、`whitelist`。配置项均通过 `config('melo-jwt')` 读取。

> **密钥长度要求**（firebase/php-jwt v7 起强制校验）：HS256 密钥至少 32 字节、HS384 至少 48 字节、HS512 至少 64 字节，否则签发时抛 `JwtException`。可用 `openssl rand -base64 48` 生成。

非 Webman 环境可直接把配置数组传给管理器：

```php
use Melo\Jwt\JwtManager;

$manager = new JwtManager(require __DIR__ . '/config/melo-jwt.php');
$jwt = $manager->guard();
```

## 快速使用

**统一签发入口** `encode()` 默认返回双令牌：

```php
use Melo\Jwt\Facade as Jwt;

// 签发：一次拿到 access + refresh
$tokens = Jwt::encode(['uid' => 1001, 'name' => 'melo'], 3600);
// ['access_token' => '...', 'refresh_token' => '...', 'token_type' => 'Bearer', 'expires_in' => 3600]

// 验证并取回 claims（接口鉴权用 access_token）
$claims = Jwt::decode($tokens['access_token']);

// 只判断有效性
Jwt::verify($tokens['access_token']);       // true / false

// 不验签解析（仅读取 exp、jti 等，勿用于鉴权）
$payload = Jwt::claims($tokens['access_token']);

// 用 refresh_token 换取新令牌（默认轮换）
$new = Jwt::refreshByToken($tokens['refresh_token']);

// 撤销 / 判断是否撤销（需开启黑名单，对单个 token）
Jwt::invalidate($tokens['access_token']);
Jwt::isBlacklisted($tokens['access_token']);

// 单点登录登出：只需用户ID，不传设备则退出全部设备
Jwt::logout(1001);            // 退出该用户所有设备
Jwt::logout(1001, 'ios');     // 只退出 ios 设备
```

全局辅助函数（大驼峰）：

```php
$tokens = JwtToken(['uid' => 1001]);          // 统一签发，返回双令牌
$guard  = Jwt();                              // 默认守卫实例
$admin  = Jwt('admin');                       // 指定守卫
$uid    = JwtClaims('uid');                   // 当前请求中的 uid（中间件注入后）
JwtVerify($tokens['access_token']);           // 校验
$new    = JwtRefresh($tokens['refresh_token']); // 刷新换令牌
JwtLogout(1001);                              // 登出全部设备
JwtLogout(1001, 'ios');                       // 登出指定设备
```

多守卫：在 `config/melo-jwt.php` 的 `guards` 中新增一组，然后 `Jwt('admin')->encode(...)`。

## 中间件

在 `config/middleware.php` 中注册：

```php
return [
    '' => [
        \Melo\Jwt\Middleware\JwtAuthMiddleware::class,
    ],
];
```

中间件**只从请求头获取 token**，默认格式：

```
Authorization: Bearer <access_token>
```

请求头缺失或格式不符时返回 401（`TokenMissingException`）。如需非标准入口显式传入，可在请求上设置属性：

```php
$request->withAttr('jwtToken', $token); // 优先于请求头
```

命中 `whitelist` 的路径直接放行。认证成功后 claims 注入到：

```php
$request->jwtClaims;          // 数组
context('jwt.claims');        // Webman 协程上下文
JwtClaims('uid');             // 辅助函数读取
```

认证失败返回统一 JSON 响应（默认 HTTP 401）：

```json
{ "code": 401, "message": "Token has expired.", "data": null }
```

可在 `exception.response` 中自定义结构，`{message}` 会被替换为具体错误。

## 黑名单（主动失效单个 token）

JWT 默认无法主动失效。开启方式：

```php
'blacklist' => [
    'enable' => true,
    'driver' => 'array',   // 或 'redis'
    'prefix' => 'melo_jwt:blacklist:',
    'redis' => [ 'host' => '127.0.0.1', 'port' => 6379, ... ],
],
```

开启后签发的 token 会自动带上 `jti`，调用 `Jwt::invalidate($token)` 即加入黑名单，剩余有效期内该 token 会被拒绝。

> `array` 驱动仅当前进程有效；Workerman 多进程或多机部署请使用 `redis` 驱动（需安装 `ext-redis`）。

## 单点登录（SSO）

以 **(用户ID, 设备类型)** 为唯一维度：`同一用户 + 同一设备` 只保留一个有效会话。统一签发时只要 claims 带 `uid` / `device`，就会覆盖同设备旧会话，旧令牌立即失效。

```php
use Melo\Jwt\Facade as Jwt;

// 用户 1001 在 ios 设备签发（uid / device 为默认声明名）
$ios = Jwt::encode(['uid' => 1001, 'device' => 'ios', 'name' => 'melo']);

// 同一用户又在 ios 签发 -> 上面那套令牌立即失效
$ios2 = Jwt::encode(['uid' => 1001, 'device' => 'ios']);

// 同一用户在 pc 签发 -> 互不影响，两个设备各自有效
$pc = Jwt::encode(['uid' => 1001, 'device' => 'pc']);

// 用户ID支持字符串
$str = Jwt::encode(['uid' => 'user-abc', 'device' => 'web']);

// 刷新：轮换时同步更新 jti，旧令牌立即失效
$new = Jwt::refreshByToken($ios2['refresh_token']);

// 登出：只需用户ID；不传设备类型则退出全部设备
Jwt::logout(1001);           // ios / pc / web 全部下线
Jwt::logout(1001, 'ios');    // 只退出 ios
```

开启配置（默认关闭）：

```php
'sso' => [
    'enable' => true,
    'driver' => 'redis',        // redis 或 mysql
    'user_claim' => 'uid',      // token 中用户ID的声明名
    'device_claim' => 'device', // token 中设备类型的声明名
    'prefix' => 'melo_jwt:sso:',
    'redis' => [ 'host' => '127.0.0.1', 'port' => 6379, ... ],

    // driver=mysql 时生效
    'table' => 'melo_jwt_sso',
    'connection' => '',         // ThinkORM 连接名，空则用默认连接
],
```

**MySQL 驱动**需安装 `topthink/think-orm` 并建表：

```bash
composer require topthink/think-orm
```

```sql
CREATE TABLE `melo_jwt_sso` (
  `id` BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  `user_id` VARCHAR(64) NOT NULL COMMENT '用户ID',
  `device_type` VARCHAR(64) NOT NULL COMMENT '设备类型',
  `jti` VARCHAR(64) NOT NULL COMMENT '当前有效token的jti',
  `expire_time` INT UNSIGNED NOT NULL COMMENT '过期时间戳',
  `create_time` INT UNSIGNED NOT NULL DEFAULT 0,
  `update_time` INT UNSIGNED NOT NULL DEFAULT 0,
  PRIMARY KEY (`id`),
  UNIQUE KEY `uk_user_device` (`user_id`, `device_type`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COMMENT='JWT单点登录状态';
```

> 说明：只有携带 `uid` / `device` 声明的 token 才受 SSO 约束；不带的 token 不受影响。SSO 记录有效期取 `refresh_ttl`（`0` 时按 10 年处理），保证 access 过期后 refresh 仍可正常使用。未开启 SSO 时调用 `logout()` 会抛 `JwtException`。

## 双令牌（access / refresh）

`encode()` 默认签发双令牌：access token 短有效期用于接口鉴权；refresh token 长有效期、使用**独立密钥**，专用于换取新令牌。两者都带 `type` 声明：refresh token 不能当 access token 用，反之亦然。

**1. 配置独立密钥**（每个 guard 各自一份）：

```php
'guards' => [
    'default' => [
        'algo' => 'HS256',
        'secret' => 'access-secret-...',            // access 密钥（>=32 字节）
        'ttl' => 3600,                              // access 有效期
        'refresh_secret' => 'refresh-secret-...',   // refresh 独立密钥（>=32 字节）
        'refresh_ttl' => 1209600,                   // refresh 有效期（14 天）
    ],
],

'refresh' => [
    'rotate' => true,        // 轮换：刷新后旧 refresh 立即失效
    'type_claim' => 'type',
    'type_value' => 'refresh',
],
```

非对称算法下，refresh 用 `refresh_private_key` / `refresh_public_key`。未配置 `refresh_secret` 时签发会抛 `JwtException`。

**2. 刷新令牌**：

```php
$tokens = Jwt::encode(['uid' => 1001]);

$new = Jwt::refreshByToken($tokens['refresh_token']);
// 返回新的 access_token + refresh_token

// 关闭轮换（旧 refresh 可继续使用）：
$new = Jwt::refreshByToken($tokens['refresh_token'], null, false);
```

- 轮换开启时，新 access 与 refresh 共享新 jti 并同步到 SSO，旧令牌（access + refresh）立即被判定为已下线。
- 刷新会校验 refresh token 的签名与类型，并在开启 SSO 时校验登录态（被踢 / 登出的 refresh token 无法刷新）。
- 旧的 `refresh($accessToken)` 单令牌刷新仍保留可用，但推荐双令牌机制。

**3. 辅助函数 / 门面**：

```php
$tokens = JwtToken(['uid' => 1001]);              // = Jwt::encode(...)
$new    = JwtRefresh($tokens['refresh_token']);   // = Jwt::refreshByToken(...)
JwtLogout(1001);                                  // = Jwt::logout(...)
```

## 非对称算法

以 RS256 为例，把公钥 / 私钥以 PEM 字符串或文件路径填入守卫配置：

```php
'guards' => [
    'default' => [
        'algo' => 'RS256',
        'private_key' => '/path/to/private.pem',  // 签发用
        'public_key'  => '/path/to/public.pem',   // 验证用
        'ttl' => 3600,
    ],
],
```

## 异常处理

所有异常继承自 `Melo\Jwt\Exception\JwtException`：

| 异常 | 含义 |
| --- | --- |
| `TokenInvalidException` | 签名错误、格式错误、缺少必要声明 |
| `TokenExpiredException` | Token 已过期 |
| `TokenBlacklistedException` | Token 已被撤销（黑名单） |
| `TokenKickedException` | 同设备已被新签发挤下线或已登出（SSO） |
| `TokenMissingException` | 请求头未携带 Token |
| `JwtException` | 配置或运行时错误 |

## License

MIT
