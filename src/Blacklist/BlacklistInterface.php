<?php

declare(strict_types=1);

namespace Melo\Jwt\Blacklist;

/**
 * Token 黑名单存储接口
 */
interface BlacklistInterface
{
    /**
     * 将 jti 加入黑名单，ttl 秒后自动失效
     */
    public function add(string $jti, int $ttl): void;

    /**
     * 判断 jti 是否在黑名单中
     */
    public function has(string $jti): bool;

    /**
     * 从黑名单中移除
     */
    public function remove(string $jti): void;

    /**
     * 清空黑名单
     */
    public function clear(): void;
}
