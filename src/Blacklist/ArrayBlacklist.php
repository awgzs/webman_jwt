<?php

declare(strict_types=1);

namespace Melo\Jwt\Blacklist;

/**
 * 基于进程内存的黑名单。
 *
 * 注意：Workerman 多进程下各进程内存独立，多进程/多机部署请改用 RedisBlacklist。
 */
class ArrayBlacklist implements BlacklistInterface
{
    /** @var array<string, int> jti => 过期时间戳 */
    private static array $items = [];

    public function add(string $jti, int $ttl): void
    {
        self::$items[$jti] = time() + $ttl;
    }

    public function has(string $jti): bool
    {
        if (!isset(self::$items[$jti])) {
            return false;
        }

        if (self::$items[$jti] <= time()) {
            unset(self::$items[$jti]);
            return false;
        }

        return true;
    }

    public function remove(string $jti): void
    {
        unset(self::$items[$jti]);
    }

    public function clear(): void
    {
        self::$items = [];
    }
}
