<?php

declare(strict_types=1);

namespace Melo\Jwt;

use Melo\Jwt\Exception\JwtException;

/**
 * JWT 静态门面（对齐 tinywan/webman-jwt 风格）。
 *
 * 所有方法委托给核心 Jwt 实例，配置从 config('melo-jwt') 加载，
 * 秘钥占位符在首次使用时自动生成。
 */
final class JwtToken
{
    public const ACCESS_TOKEN = 1;
    public const REFRESH_TOKEN = 2;

    public const TOKEN_CLIENT_WEB = 'WEB';
    public const TOKEN_CLIENT_MOBILE = 'MOBILE';
    public const TOKEN_CLIENT_APP = 'APP';
    public const TOKEN_CLIENT_WECHAT = 'WECHAT';
    public const TOKEN_CLIENT_ADMIN = 'ADMIN';
    public const TOKEN_CLIENT_API = 'API';
    public const TOKEN_CLIENT_OTHER = 'OTHER';

    private static ?JwtManager $manager = null;

    /**
     * 统一签发：返回 access_token + refresh_token。
     *
     * @param array    $extend      业务字段，必须含配置的 id 字段（默认 id）
     * @param int|null $accessExp   覆盖 access 有效期
     * @param int|null $refreshExp  覆盖 refresh 有效期
     * @return array{token_type: string, expires_in: int, access_token: string, refresh_token?: string}
     */
    public static function generateToken(array $extend, ?int $accessExp = null, ?int $refreshExp = null): array
    {
        return self::jwt()->encode($extend, $accessExp, $refreshExp);
    }

    /**
     * 校验令牌，返回完整载荷（含 extend）。未传 token 时从请求头获取。
     */
    public static function verify(int $tokenType = self::ACCESS_TOKEN, ?string $token = null): array
    {
        return self::jwt()->verify($tokenType, $token);
    }

    /**
     * 获取当前登录用户ID
     */
    public static function getCurrentId(?string $token = null): int|string
    {
        return self::jwt()->getCurrentId($token);
    }

    /**
     * 获取所有业务字段
     */
    public static function getExtend(?string $token = null): array
    {
        return self::jwt()->getExtend($token);
    }

    /**
     * 获取指定业务字段
     */
    public static function getExtendVal(string $key, mixed $default = '', ?string $token = null): mixed
    {
        return self::jwt()->getExtendVal($key, $default, $token);
    }

    /**
     * 刷新令牌：用 refresh token 换取新令牌。未传则从请求头获取。
     *
     * @param array $extend 引用返回业务字段
     * @return array{token_type: string, expires_in: int, access_token: string, refresh_token?: string}
     */
    public static function refreshToken(?string $refreshToken = null, array &$extend = []): array
    {
        return self::jwt()->refreshToken($refreshToken, $extend);
    }

    /**
     * 获取 token 剩余有效期（秒）
     */
    public static function getTokenExp(int $tokenType = self::ACCESS_TOKEN, ?string $token = null): int
    {
        return self::jwt()->getTokenExp($tokenType, $token);
    }

    /**
     * 获取当前登录用户（由配置的 user_model 回调返回）
     */
    public static function getUser(?string $token = null): mixed
    {
        return self::jwt()->getUser($token);
    }

    /**
     * 令牌清理（退出登录）：只需用户ID，不传客户端则退出全部设备。
     */
    public static function clear(string|int $userId, ?string $client = null): void
    {
        self::jwt()->clear($userId, $client);
    }

    /**
     * 撤销单个 token（需开启黑名单）
     */
    public static function invalidate(string $token): void
    {
        self::jwt()->invalidate($token);
    }

    /**
     * 判断是否已撤销
     */
    public static function isBlacklisted(string $token): bool
    {
        return self::jwt()->isBlacklisted($token);
    }

    /**
     * 获取核心 Jwt 实例
     */
    public static function jwt(): Jwt
    {
        return self::manager()->guard();
    }

    public static function manager(): JwtManager
    {
        if (self::$manager === null) {
            self::$manager = new JwtManager(ConfigLoader::load());
        }
        return self::$manager;
    }

    /**
     * 运行时替换管理器（便于测试或动态切换配置）
     */
    public static function setManager(?JwtManager $manager): void
    {
        self::$manager = $manager;
    }

    /**
     * 运行时读取配置
     */
    public static function config(string $key, mixed $default = null): mixed
    {
        return self::manager()->config($key, $default);
    }
}
