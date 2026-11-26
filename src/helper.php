<?php

declare(strict_types=1);

use Melo\Jwt\Exception\JwtException;

if (!function_exists('Jwt')) {
    /**
     * 获取 JWT 守卫实例。
     *
     *   Jwt()             -> 默认守卫
     *   Jwt('admin')      -> 指定守卫
     *   Jwt()->encode([...])
     */
    function Jwt(?string $guard = null): \Melo\Jwt\Jwt
    {
        return \Melo\Jwt\Facade::guard($guard);
    }
}

if (!function_exists('JwtToken')) {
    /**
     * 统一签发：默认返回 access + refresh 双令牌。
     * claims 中带 uid / device 且开启 SSO 时，自动绑定单点登录态。
     *
     * @return array{access_token: string, refresh_token: string, token_type: string, expires_in: int}
     */
    function JwtToken(array $claims, ?int $ttl = null, ?string $guard = null): array
    {
        return Jwt($guard)->encode($claims, $ttl);
    }
}

if (!function_exists('JwtRefresh')) {
    /**
     * 用 refresh token 换取新令牌（默认轮换）
     *
     * @return array{access_token: string, refresh_token: string, token_type: string, expires_in: int}
     */
    function JwtRefresh(string $refreshToken, ?int $ttl = null, ?bool $rotate = null, ?string $guard = null): array
    {
        return Jwt($guard)->refreshByToken($refreshToken, $ttl, $rotate);
    }
}

if (!function_exists('JwtLogout')) {
    /**
     * 登出：只需要用户ID；不传设备类型则退出该用户全部设备。
     */
    function JwtLogout(string|int $userId, ?string $deviceType = null, ?string $guard = null): void
    {
        Jwt($guard)->logout($userId, $deviceType);
    }
}

if (!function_exists('JwtClaims')) {
    /**
     * 读取当前请求中已认证的 claims（由中间件注入上下文）。
     *
     * @param string|null $key 只取某个声明；null 返回全部
     */
    function JwtClaims(?string $key = null, mixed $default = null): mixed
    {
        $claims = null;
        if (function_exists('context')) {
            $claims = context('jwt.claims');
        }

        if (!is_array($claims)) {
            return $key === null ? [] : $default;
        }

        if ($key === null) {
            return $claims;
        }
        return array_key_exists($key, $claims) ? $claims[$key] : $default;
    }
}

if (!function_exists('JwtVerify')) {
    /**
     * 校验 token 是否有效
     */
    function JwtVerify(string $token, ?string $guard = null): bool
    {
        try {
            Jwt($guard)->decode($token);
            return true;
        } catch (JwtException) {
            return false;
        }
    }
}
