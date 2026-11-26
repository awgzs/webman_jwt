<?php

declare(strict_types=1);

namespace Melo\Jwt;

/** 兼容层，推荐直接使用 JwtToken。 */
final class Facade
{
    public static function manager(): JwtManager
    {
        return JwtToken::manager();
    }

    public static function guard(?string $name = null): Jwt
    {
        return JwtToken::jwt();
    }

    public static function encode(array $extend, ?int $accessExp = null, ?int $refreshExp = null): array
    {
        return JwtToken::generateToken($extend, $accessExp, $refreshExp);
    }

    public static function refreshToken(?string $refreshToken = null, array &$extend = []): array
    {
        return JwtToken::refreshToken($refreshToken, $extend);
    }

    public static function verify(int $tokenType = JwtToken::ACCESS_TOKEN, ?string $token = null): array
    {
        return JwtToken::verify($tokenType, $token);
    }

    public static function setManager(?JwtManager $manager): void
    {
        JwtToken::setManager($manager);
    }

    public static function __callStatic(string $method, array $arguments): mixed
    {
        return JwtToken::jwt()->{$method}(...$arguments);
    }
}
