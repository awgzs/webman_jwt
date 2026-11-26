<?php

declare(strict_types=1);

namespace Melo\Jwt;

/**
 * JWT 静态门面。
 *
 * 默认从 Webman 的 config('melo-jwt') 读取配置；
 * 未安装 Webman 或函数不存在时，回退加载包内 config/melo-jwt.php。
 */
final class Facade
{
    private static ?JwtManager $manager = null;

    /**
     * 获取管理器实例（单例）
     */
    public static function manager(): JwtManager
    {
        if (self::$manager === null) {
            self::$manager = new JwtManager(self::loadConfig());
        }
        return self::$manager;
    }

    /**
     * 获取指定守卫，未传则默认守卫
     */
    public static function guard(?string $name = null): Jwt
    {
        return self::manager()->guard($name);
    }

    /**
     * 统一签发：一次返回 access + refresh 双令牌
     *
     * @return array{access_token: string, refresh_token: string, token_type: string, expires_in: int}
     */
    public static function encode(array $claims, ?int $ttl = null, ?string $guard = null): array
    {
        return self::guard($guard)->encode($claims, $ttl);
    }

    /**
     * 用 refresh token 换取新令牌
     *
     * @return array{access_token: string, refresh_token: string, token_type: string, expires_in: int}
     */
    public static function refreshByToken(string $refreshToken, ?int $ttl = null, ?bool $rotate = null, ?string $guard = null): array
    {
        return self::guard($guard)->refreshByToken($refreshToken, $ttl, $rotate);
    }

    /**
     * 登出：只需要用户ID；不传设备类型则退出该用户全部设备
     */
    public static function logout(string|int $userId, ?string $deviceType = null, ?string $guard = null): void
    {
        self::guard($guard)->logout($userId, $deviceType);
    }

    /**
     * 运行时替换管理器（便于测试或动态切换配置）
     */
    public static function setManager(?JwtManager $manager): void
    {
        self::$manager = $manager;
    }

    /**
     * 所有未定义静态方法调用转发到默认守卫。
     *
     * @param array<int, mixed> $arguments
     */
    public static function __callStatic(string $method, array $arguments): mixed
    {
        return self::guard()->{$method}(...$arguments);
    }

    private static function loadConfig(): array
    {
        if (function_exists('config')) {
            $config = config('melo-jwt');
            if (is_array($config) && $config !== []) {
                return $config;
            }
        }

        $file = dirname(__DIR__) . '/config/melo-jwt.php';
        if (is_file($file)) {
            $config = require $file;
            if (is_array($config)) {
                return $config;
            }
        }

        return [];
    }
}
