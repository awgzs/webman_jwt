<?php

declare(strict_types=1);

namespace Melo\Jwt\Blacklist;

interface BlacklistInterface
{
    public function add(string $jti, int $ttl): void;

    public function has(string $jti): bool;

    public function remove(string $jti): void;

    public function clear(): void;
}
