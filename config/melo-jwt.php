<?php

declare(strict_types=1);

/**
 * Melo JWT 配置模板
 *
 * 使用方式：把本文件复制到 Webman 应用的 config/ 目录下，
 * 即 config/melo-jwt.php，然后通过 config('melo-jwt') 读取。
 */
return [
    // 是否启用（关闭后中间件直接放行）
    'enable' => true,

    // 默认守卫名称，对应 guards 中的键
    'default' => 'default',

    /*
    |--------------------------------------------------------------------------
    | 守卫配置
    |--------------------------------------------------------------------------
    | 可配置多套独立签名策略，例如 API 与后台使用不同密钥和有效期。
    | 使用时通过 Jwt::guard('admin') 或 Jwt('admin') 切换。
    */
    'guards' => [
        'default' => [
            // 签名算法：HS256 / HS384 / HS512 / RS256 / RS384 / RS512 / ES256 / EdDSA
            'algo' => 'HS256',

            // HMAC 密钥（HS* 系列使用）。务必替换为随机强密钥！
            'secret' => 'change-me-to-a-long-random-secret-key',

            // 非对称算法密钥（RS*/ES*/EdDSA），支持 PEM 字符串或文件路径
            'public_key' => null,
            'private_key' => null,

            // token 有效期（秒）；0 表示永不过期
            'ttl' => 3600,

            // 允许的时间偏差（秒），容忍服务器时钟差异
            'leeway' => 0,

            // JWT 标准声明：签发者、受众、主体
            'issuer' => null,
            'audience' => null,
            'subject' => null,

            // 是否要求 token 必须带有 exp 声明
            'require_exp' => true,

            // 签发时默认写入的自定义 claims（会被传入的 claims 覆盖）
            'claims' => [],

            /*
            | 独立 refresh token 密钥（双令牌机制）
            | refresh token 必须使用与 access token 不同的密钥。
            | HS 系列用 refresh_secret；RS/ES/EdDSA 用 refresh_private_key 与 refresh_public_key。
            | encode() 签发双令牌与 refreshByToken() 均需要此密钥。
            */
            'refresh_secret' => 'change-me-to-another-long-random-secret-key',

            'refresh_private_key' => null,
            'refresh_public_key' => null,

            // refresh token 有效期（秒），默认 14 天；0 表示永不过期
            'refresh_ttl' => 1209600,
        ],

        // 'admin' => [
        //     'algo' => 'HS512',
        //     // HS512 要求密钥 >= 64 字节
        //     'secret' => 'another-long-random-secret-at-least-64-bytes-xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx',
        //     // encode() 签发双令牌，每个守卫都必须配置独立 refresh 密钥
        //     'refresh_secret' => 'another-long-random-refresh-secret-at-least-64-bytes-xxxxxxxxxxxxxx',
        //     'ttl' => 7200,
        // ],
    ],

    /*
    |--------------------------------------------------------------------------
    | Token 提取规则
    |--------------------------------------------------------------------------
    | 中间件只从请求头获取 token，取不到则报 401。
    | 需非标准入口时，可在请求上显式设置 $request->jwtToken。
    */
    'token' => [
        // 请求头名称与前缀，例如：Authorization: Bearer <token>
        'header' => 'Authorization',
        'prefix' => 'Bearer',
    ],

    /*
    |--------------------------------------------------------------------------
    | 白名单
    |--------------------------------------------------------------------------
    | 命中白名单的路径跳过 JWT 认证。支持完整路径或前缀（以 * 结尾）。
    */
    'whitelist' => [
        // '/api/login',
        // '/api/health*',
    ],

    /*
    |--------------------------------------------------------------------------
    | 黑名单
    |--------------------------------------------------------------------------
    | 用于 logout 等场景主动使 token 失效，基于 jti 声明实现。
    | array 驱动仅当前进程有效；多进程/多机部署请用 redis 驱动。
    */
    'blacklist' => [
        'enable' => false,

        // array 或 redis
        'driver' => 'array',

        'prefix' => 'melo_jwt:blacklist:',

        'redis' => [
            'host' => '127.0.0.1',
            'port' => 6379,
            'password' => null,
            'database' => 0,
            'timeout' => 0.0,
        ],
    ],

    /*
    |--------------------------------------------------------------------------
    | 单点登录（SSO）
    |--------------------------------------------------------------------------
    | 以 (用户ID, 设备类型) 为维度，同一用户在同一设备只允许一个有效 token。
    | 统一通过 encode(['uid' => ..., 'device' => ...]) 签发；新签发会挤掉旧 token。
    | 登出 Jwt::logout($userId) 不传设备则退出该用户全部设备。
    | 驱动：redis 或 mysql(thinkorm)。mysql 需先建表（见 README）并安装 think-orm。
    */
    'sso' => [
        'enable' => false,

        // redis 或 mysql（thinkorm 是 mysql 的别名）
        'driver' => 'redis',

        // token 中存放用户ID / 设备类型的声明名
        'user_claim' => 'uid',
        'device_claim' => 'device',

        'prefix' => 'melo_jwt:sso:',

        'redis' => [
            'host' => '127.0.0.1',
            'port' => 6379,
            'password' => null,
            'database' => 0,
            'timeout' => 0.0,
        ],

        // 仅 driver=mysql 时生效
        'table' => 'melo_jwt_sso',
        'connection' => '',
    ],

    /*
    |--------------------------------------------------------------------------
    | 双令牌（access / refresh）
    |--------------------------------------------------------------------------
    | refresh token 使用 guard 中独立的 refresh_* 密钥签发，携带 type=refresh 声明，
    | 仅能用于 refreshByToken()，不能作为 access token 访问接口。
    */
    'refresh' => [
        // 刷新时是否轮换 refresh token（轮换后旧 refresh token 立即失效）
        'rotate' => true,

        // refresh token 的类型声明名与值（用于防止 access token 被当作 refresh token）
        'type_claim' => 'type',
        'type_value' => 'refresh',
    ],

    /*
    |--------------------------------------------------------------------------
    | 异常处理
    |--------------------------------------------------------------------------
    */
    'exception' => [
        // 认证失败时返回的 HTTP 状态码
        'status' => 401,

        // 响应结构，{message} 会替换为具体错误信息
        'response' => [
            'code' => 401,
            'message' => '{message}',
            'data' => null,
        ],

        'log' => true,
    ],
];
