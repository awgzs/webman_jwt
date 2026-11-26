# melo/jwt

基于 `firebase/php-jwt` 的 JWT 认证 Composer 包，专为 Webman / Workerman 设计，API 风格参考 [tinywan/webman-jwt](https://github.com/tinywan/webman-jwt)。

- 统一签发：`generateToken()` 一次返回 `access_token` + `refresh_token`，双密钥独立
- 业务字段统一收进 `extend`，支持 `iss` / `aud` / `nbf` / `leeway`
- 秘钥占位符首次使用时**自动生成 64 位随机值并写回配置**
- 单设备登录（Redis / MySQL ThinkORM）：同用户同客户端只保留一个有效会话
- 分层异常 + tinywan 风格错误码（401011 / 401013 / 401021 ...）
- Webman 认证中间件，仅从请求头取 token
- 大驼峰辅助函数

## 安装

```bash
composer require melo/jwt
```

安装时 webman 会自动把配置模板复制到应用的 `config/plugin/melo/jwt/app.php`（插件遵循 webman 的 `WEBMAN_PLUGIN` 安装约定）。已存在的配置文件不会被覆盖。

## 配置

秘钥占位符会在首次加载配置时自动替换为 64 位随机值并写回 `config/plugin/melo/jwt/app.php`，无需手动生成。若应用侧尚未复制配置模板（例如非 webman 环境或未触发安装钩子），首次使用时也会自动创建目录与配置文件。

> 密钥长度要求（firebase/php-jwt v7）：HS256 ≥ 32 字节、HS384 ≥ 48 字节、HS512 ≥ 64 字节。

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
// ['token_type'=>'Bearer', 'expires_in'=>7200, 'access_token'=>'...', 'refresh_token'=>'...']

// 单次覆盖有效期
$tokens = JwtToken::generateToken(['id' => 1001], 3600, 604800);
```

## 支持的函数列表

**1. 获取当前登录ID**

```php
$id = JwtToken::getCurrentId();
```

**2. 获取所有扩展字段 / 指定字段**

```php
$extend = JwtToken::getExtend();
$email  = JwtToken::getExtendVal('email');
```

**3. 校验令牌**（未传 token 时自动从请求头 `Authorization: Bearer` 获取）

```php
$payload = JwtToken::verify(JwtToken::ACCESS_TOKEN);
```

**4. 刷新令牌**

```php
$new = JwtToken::refreshToken();               // 从请求头取 refresh token
$new = JwtToken::refreshToken($refreshToken);  // 显式传入
```

**5. 获取令牌剩余有效期（秒）**

```php
$exp = JwtToken::getTokenExp();
```

**6. 令牌清理（退出登录）**

只需用户ID，不传客户端则退出该用户全部设备：

```php
JwtToken::clear(1001);                          // 全部设备
JwtToken::clear(1001, JwtToken::TOKEN_CLIENT_WEB); // 仅 WEB
```

**7. 获取当前用户信息（模型）**

配置 `user_model` 回调后可用：

```php
'user_model' => function ($uid) {
    return \think\facade\Db::table('user')->where('id', $uid)->find();
},
```

```php
$user = JwtToken::getUser();
```

**8. 自定义客户端类型**

```php
JwtToken::generateToken(['id' => 1001, 'client' => JwtToken::TOKEN_CLIENT_MOBILE]);
```

内置常量：`WEB` / `MOBILE` / `APP` / `WECHAT` / `ADMIN` / `API` / `OTHER`。

**9. 撤销单个 token（需开启黑名单）**

```php
JwtToken::invalidate($token);
JwtToken::isBlacklisted($token);
```

## 大驼峰辅助函数

```php
$tokens = JwtToken(['id' => 1001]);            // 统一签发
$ok     = JwtVerify($token);                    // 校验
$new    = JwtRefresh();                         // 刷新
JwtClear(1001);                                 // 退出
$uid    = JwtCurrentId();                       // 当前用户ID
$name   = JwtClaims('name');                    // 指定扩展字段
$all    = JwtClaims();                          // 全部扩展字段
$jwt    = Jwt();                                // 核心 Jwt 实例
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

中间件**只从请求头获取 token**：

```
Authorization: Bearer <access_token>
```

命中 `whitelist` 的路径直接放行。认证成功后载荷注入到：

```php
$request->jwtClaims;      // 数组
context('jwt.claims');    // Webman 协程上下文
JwtClaims('uid');         // 辅助函数读取（注意 extend 中字段名默认为 id）
```

认证失败返回统一 JSON 响应（默认 HTTP 401）：

```json
{ "code": 401013, "message": "身份验证会话已过期，请重新登录！", "data": null }
```

## 单设备登录（SSO）

启用配置：

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
