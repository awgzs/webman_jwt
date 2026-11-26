<?php

declare(strict_types=1);

namespace Melo\Jwt;

use Melo\Jwt\Exception\JwtException;

/** 静态门面，方法委托给核心 Jwt 实例。 */
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
     * @param array    $extend      业务字段，必须含配置的 id 字段（默认 id）
     * @param int|null $accessExp   覆盖 access 有效期
     * @param int|null $refreshExp  覆盖 refresh 有效期
     * @return array{token_type: string, expires_in: int, access_token: string, refresh_token?: string}
     */
    public static function generateToken(array $extend, ?int $accessExp = null, ?int $refreshExp = null): array
    {
        return self::jwt()->encode($extend, $accessExp, $refreshExp);
    }

    public static function verify(int $tokenType = self::ACCESS_TOKEN, ?string $token = null): array
    {
        return self::jwt()->verify($tokenType, $token);
    }

    public static function getCurrentId(?string $token = null): int|string
    {
        return self::jwt()->getCurrentId($token);
    }

    public static function getExtend(?string $token = null): array
    {
        return self::jwt()->getExtend($token);
    }

    public static function getExtendVal(string $key, mixed $default = '', ?string $token = null): mixed
    {
        return self::jwt()->getExtendVal($key, $default, $token);
    }

    /**
     * @param array $extend 引用返回业务字段
     * @return array{token_type: string, expires_in: int, access_token: string, refresh_token?: string}
     */
    public static function refreshToken(?string $refreshToken = null, array &$extend = []): array
    {
        return self::jwt()->refreshToken($refreshToken, $extend);
    }

    public static function getTokenExp(int $tokenType = self::ACCESS_TOKEN, ?string $token = null): int
    {
        return self::jwt()->getTokenExp($tokenType, $token);
    }

    public static function getUser(?string $token = null): mixed
    {
        return self::jwt()->getUser($token);
    }

    /** 不传客户端则退出全部设备。 */
    public static function clear(string|int $userId, ?string $client = null): void
    {
        self::jwt()->clear($userId, $client);
    }

    /** 需开启黑名单。 */
    public static function invalidate(string $token): void
    {
        self::jwt()->invalidate($token);
    }

    public static function isBlacklisted(string $token): bool
    {
        return self::jwt()->isBlacklisted($token);
    }

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

    public static function setManager(?JwtManager $manager): void
    {
        self::$manager = $manager;
    }

    public static function config(string $key, mixed $default = null): mixed
    {
        return self::manager()->config($key, $default);
    }
}
