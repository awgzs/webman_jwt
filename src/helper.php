<?php

declare(strict_types=1);

use Melo\Jwt\Exception\JwtException;
use Melo\Jwt\JwtToken;

if (!function_exists('Jwt')) {
    /**
     * 获取核心 Jwt 实例。
     */
    function Jwt(): \Melo\Jwt\Jwt
    {
        return JwtToken::jwt();
    }
}

if (!function_exists('JwtToken')) {
    /**
     * 统一签发：返回 access_token + refresh_token。
     *
     * @return array{token_type: string, expires_in: int, access_token: string, refresh_token?: string}
     */
    function JwtToken(array $extend, ?int $accessExp = null, ?int $refreshExp = null): array
    {
        return \Melo\Jwt\JwtToken::generateToken($extend, $accessExp, $refreshExp);
    }
}

if (!function_exists('JwtVerify')) {
    /**
     * 校验 token 是否有效（不抛异常）
     */
    function JwtVerify(string $token, int $tokenType = \Melo\Jwt\JwtToken::ACCESS_TOKEN): bool
    {
        try {
            \Melo\Jwt\JwtToken::verify($tokenType, $token);
            return true;
        } catch (JwtException) {
            return false;
        }
    }
}

if (!function_exists('JwtRefresh')) {
    /**
     * 刷新令牌
     *
     * @return array{token_type: string, expires_in: int, access_token: string, refresh_token?: string}
     */
    function JwtRefresh(?string $refreshToken = null, array &$extend = []): array
    {
        return \Melo\Jwt\JwtToken::refreshToken($refreshToken, $extend);
    }
}

if (!function_exists('JwtClear')) {
    /**
     * 退出登录：只需用户ID；不传客户端则退出全部设备
     */
    function JwtClear(string|int $userId, ?string $client = null): void
    {
        \Melo\Jwt\JwtToken::clear($userId, $client);
    }
}

if (!function_exists('JwtClaims')) {
    /**
     * 获取当前 token 的业务字段（或指定字段）
     */
    function JwtClaims(?string $key = null, mixed $default = '', ?string $token = null): mixed
    {
        if ($key === null) {
            return \Melo\Jwt\JwtToken::getExtend($token);
        }
        return \Melo\Jwt\JwtToken::getExtendVal($key, $default, $token);
    }
}

if (!function_exists('JwtCurrentId')) {
    /**
     * 获取当前登录用户ID
     */
    function JwtCurrentId(?string $token = null): int|string
    {
        return \Melo\Jwt\JwtToken::getCurrentId($token);
    }
}
