<?php

declare(strict_types=1);

namespace Melo\Jwt\Sso;

/** 以 (userId, deviceType) 为唯一键，新签发覆盖旧 jti，旧 token 校验时判定为下线。 */
interface SsoInterface
{
    public function store(string|int $userId, string $deviceType, string $jti, int $ttl): void;

    public function get(string|int $userId, string $deviceType): ?string;

    public function logout(string|int $userId, string $deviceType): void;

    public function logoutAll(string|int $userId): void;
}
