# melo/jwt

基于 `firebase/php-jwt` 的 JWT 认证 Composer 包，专为 Webman / Workerman 设计。

- 统一签发 `generateToken()`：一次返回 access + refresh（及各有效期），双密钥独立
- 业务字段统一收进 `extend`，支持 `iss` / `aud` / `nbf` / `leeway`
- 安装时秘钥占位符**自动生成 64 位随机值并写回配置**
- 单设备登录（Redis / MySQL ThinkORM）：同用户同客户端只保留一个有效会话
- 分层异常 + tinywan 风格错误码（401011 / 401013 / 401021 ...）
- Webman 认证中间件，仅从请求头取 token
- 大驼峰辅助函数

## 安装

```bash
composer require melo/jwt
```

webman 会自动复制配置模板到 `config/plugin/melo/jwt/app.php`，已存在的文件不覆盖，并把秘钥占位符替换为随机值写回。已生成的秘钥不会被覆盖。

## 配置

若模板未被复制（如非 webman 环境），秘钥占位符会在首次使用时自动生成并写回 `config/plugin/melo/jwt/app.php`。

> 密钥长度要求（firebase/php-jwt v7）：HS256 ≥ 32 字节、HS384 ≥ 48 字节、HS512 ≥ 64 字节。

### 返回前端的字段名

签发结果里的字段名可通过 `response_fields` 配置，键为内部字段名，值为返回前端的字段名；未列出的字段保持原名：

```php
'response_fields' => [
    'token_type' => 'token_type',
    'access_token' => 'access_token',
    'access_expires_in' => 'expires_in',      // 例如改回 expires_in
    'refresh_token' => 'refresh_token',
    'refresh_expires_in' => 'refresh_expires_in',
],
```

默认把 access 有效期字段命名为 `access_expires_in`，与 `refresh_expires_in` 对称。

## 快速使用

```php
use Melo\Jwt\JwtToken;

// 统一签发（必须含 id 字段）
$tokens = JwtToken::generateToken([
    'id' => 1001,
    'name' => 'melo',
    'email' => 'melo@example.com',
    'client' => JwtToken::TOKEN_CLIENT_WEB,
]);
// ['token_type'=>'Bearer', 'access_expires_in'=>7200, 'access_token'=>'...', 'refresh_token'=>'...', 'refresh_expires_in'=>604800]

$tokens = JwtToken::generateToken(['id' => 1001], 3600, 604800); // 单次覆盖有效期
```

## 函数速查

```php
$id      = JwtToken::getCurrentId();                // 当前登录 ID
$all     = JwtToken::getExtend();                   // 全部业务字段
$email   = JwtToken::getExtendVal('email');         // 指定业务字段
$payload = JwtToken::verify(JwtToken::ACCESS_TOKEN); // 校验，未传 token 时从请求头取
$user    = JwtToken::getUser();                     // 当前用户（需配置 user_model 回调）
$exp     = JwtToken::getTokenExp();                 // 剩余有效期（秒）

$new = JwtToken::refreshToken();                    // 刷新，未传则从请求头取
$new = JwtToken::refreshToken($refreshToken);       // 显式传入

JwtToken::clear(1001);                              // 退出该用户全部设备
JwtToken::clear(1001, JwtToken::TOKEN_CLIENT_WEB);   // 仅退出 WEB

JwtToken::invalidate($token);                       // 撤销单个 token（需开启黑名单）
JwtToken::isBlacklisted($token);
```

客户端常量：`WEB` / `MOBILE` / `APP` / `WECHAT` / `ADMIN` / `API` / `OTHER`，通过 `client` 字段传入：

```php
JwtToken::generateToken(['id' => 1001, 'client' => JwtToken::TOKEN_CLIENT_MOBILE]);
```

`user_model` 回调示例：

```php
'user_model' => function ($uid) {
    return \think\facade\Db::table('user')->where('id', $uid)->find();
},
```

## 大驼峰辅助函数

```php
$tokens = JwtToken(['id' => 1001]); // 统一签发
$ok     = JwtVerify($token);        // 校验
$new    = JwtRefresh();             // 刷新
JwtClear(1001);                     // 退出
$uid    = JwtCurrentId();           // 当前用户 ID
$name   = JwtClaims('name');        // 指定业务字段
$all    = JwtClaims();              // 全部业务字段
$jwt    = Jwt();                    // 核心 Jwt 实例
```

## 中间件

在 `config/middleware.php` 中注册：

```php
return [
    '' => [
        \Melo\Jwt\Middleware\JwtAuthMiddleware::class,
    ],
];
```

仅从请求头获取 token：`Authorization: Bearer <access_token>`；命中 `whitelist` 的路径直接放行。认证成功后载荷注入到：

```php
$request->jwtClaims;      // 数组
context('jwt.claims');    // Webman 协程上下文
JwtClaims('uid');         // 辅助函数读取（extend 中字段名默认为 id）
```

认证失败返回统一 JSON 响应（默认 HTTP 401）：

```json
{ "code": 401013, "msg": "身份验证会话已过期，请重新登录！", "data": null }
```

## 单设备登录（SSO）

```php
'jwt' => [
    // ...
    'is_single_device' => true,
    'sso_driver' => 'redis',   // redis 或 mysql（thinkorm）
    'cache_token_pre' => 'JWT:TOKEN:',
    'cache_refresh_token_pre' => 'JWT:REFRESH_TOKEN:',
    'cache_token_ttl' => 604800,
],
```

签发时 extend 中带 `id` + `client` 即纳入单设备登录：同用户同客户端的旧令牌立即失效。

**MySQL 驱动**需安装 `topthink/think-orm` 并建表：

```bash
composer require topthink/think-orm
```

```sql
CREATE TABLE `melo_jwt_sso` (
  `id` BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  `user_id` VARCHAR(64) NOT NULL COMMENT '用户ID',
  `device_type` VARCHAR(64) NOT NULL COMMENT '客户端类型',
  `jti` VARCHAR(64) NOT NULL COMMENT '当前有效token的jti',
  `expire_time` INT UNSIGNED NOT NULL COMMENT '过期时间戳',
  `create_time` INT UNSIGNED NOT NULL DEFAULT 0,
  `update_time` INT UNSIGNED NOT NULL DEFAULT 0,
  PRIMARY KEY (`id`),
  UNIQUE KEY `uk_user_device` (`user_id`, `device_type`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COMMENT='JWT单设备登录状态';
```

## 错误码

| 错误码 | 含义 |
| --- | --- |
| 401000 | 请求未携带 authorization / 配置错误 |
| 401001 | 非法的 authorization 信息 |
| 401011 | 身份验证令牌无效 |
| 401012 | 身份验证令牌尚未生效 |
| 401013 | 身份验证会话已过期，请重新登录 |
| 401014 | 获取的扩展字段不存在 |
| 401015 | 访问令牌未知错误 / 已被撤销 |
| 401021 | 刷新令牌无效 |
| 401022 | 刷新令牌尚未生效 |
| 401023 | 刷新令牌会话已过期，请再次登录 |
| 401024 | 刷新令牌获取的扩展字段不存在 |
| 401025 | 刷新令牌未知错误 |

所有异常继承自 `Melo\Jwt\Exception\JwtException`。

## License

MIT
