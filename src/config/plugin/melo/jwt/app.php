<?php

declare(strict_types=1);

/**
 * Melo JWT 配置模板
 *
 * 使用方式：把本目录复制到 Webman 应用的 config/plugin/melo/ 目录下，
 * 即 config/plugin/melo/jwt/app.php，然后通过 config('plugin.melo.jwt.app') 读取。
 *
 * 秘钥占位符会在首次使用时自动生成 64 位随机值并写回本文件。
 */
return [
    // 是否启用（关闭后中间件直接放行）
    'enable' => true,

    /*
    |--------------------------------------------------------------------------
    | JWT 核心配置
    |--------------------------------------------------------------------------
    | 键名风格参考 tinywan/webman-jwt，便于迁移。
    */
    'jwt' => [
        // 签名算法：HS256 / HS384 / HS512 / RS256 / RS384 / RS512 / ES256 / EdDSA
        'algorithms' => 'HS256',

        // access token 秘钥。占位符会在首次使用时自动替换为 64 位随机值
        'access_secret_key' => '__MELO_JWT_ACCESS_SECRET__',

        // access token 有效期（秒），签发结果中以 access_expires_in 返回
        'access_exp' => 7200,

        // refresh token 秘钥（必须与 access 不同）。占位符同样自动生成
        'refresh_secret_key' => '__MELO_JWT_REFRESH_SECRET__',

        // refresh token 有效期（秒），签发结果中以 refresh_expires_in 返回
        'refresh_exp' => 604800,

        // 是否禁用 refresh token
        'refresh_disable' => false,

        // 签发者 / 接收方
        'iss' => 'melo-jwt',
        'aud' => 'melo-jwt-client',

        // 多少秒后才能使用（nbf）
        'nbf' => 0,

        // 允许的时间偏差（秒）
        'leeway' => 60,

        // 是否启用单设备登录（同一用户同一客户端只保留一个有效会话）
        'is_single_device' => false,

        // 单设备登录缓存配置
        'cache_token_ttl' => 604800,
        'cache_token_pre' => 'JWT:TOKEN:',
        'cache_refresh_token_pre' => 'JWT:REFRESH_TOKEN:',

        // 单设备登录存储驱动：redis 或 mysql(thinkorm)
        'sso_driver' => 'redis',
        'sso_table' => 'melo_jwt_sso',
        'sso_connection' => '',

        // 用户ID / 客户端类型的声明名（放在 extend 中）
        'id_field' => 'id',
        'client_field' => 'client',

        // 获取当前登录用户模型（可选）
        'user_model' => function ($uid) {
            return [];
        },

        // 是否允许 GET 参数传递 token（默认关闭，仅从请求头获取）
        'is_support_get_token' => false,
        'is_support_get_token_key' => 'authorization',
    ],

    /*
    |--------------------------------------------------------------------------
    | 签发结果字段映射
    |--------------------------------------------------------------------------
    | 键为内部字段名，值为返回前端的字段名；未列出的字段按键名原样返回。
    */
    'response_fields' => [
        'token_type' => 'token_type',
        'access_token' => 'access_token',
        'access_expires_in' => 'access_expires_in',
        'refresh_token' => 'refresh_token',
        'refresh_expires_in' => 'refresh_expires_in',
    ],

    /*
    |--------------------------------------------------------------------------
    | Token 提取规则
    |--------------------------------------------------------------------------
    | 默认从 Authorization: Bearer <token> 获取。
    */
    'token' => [
        'header' => 'Authorization',
        'prefix' => 'Bearer',
    ],

    /*
    |--------------------------------------------------------------------------
    | 路径白名单
    |--------------------------------------------------------------------------
    | 支持完整路径与以 * 结尾的前缀，例如 '/api/login'、'/api/public/*'
    */
    'whitelist' => [],

    /*
    |--------------------------------------------------------------------------
    | 黑名单（主动失效单个 token）
    |--------------------------------------------------------------------------
    */
    'blacklist' => [
        'enable' => false,
        'driver' => 'array',   // array 或 redis
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
    | 异常处理
    |--------------------------------------------------------------------------
    */
    'exception' => [
        'status' => 401,
        'response' => [
            'code' => 401,
            'msg' => '{msg}',
            'data' => null,
        ],
        'log' => true,
    ],
];
