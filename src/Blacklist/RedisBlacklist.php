<?php

declare(strict_types=1);

namespace Melo\Jwt\Blacklist;

use Melo\Jwt\Exception\JwtException;

class RedisBlacklist implements BlacklistInterface
{
    private array $config;
    private string $prefix;
    /** @var \Redis|null */
    private $client = null;

    public function __construct(array $config = [], string $prefix = 'melo_jwt:blacklist:')
    {
        if (!extension_loaded('redis')) {
            throw new JwtException('The redis extension is required for the redis blacklist driver.');
        }
        $this->config = $config;
        $this->prefix = $prefix;
    }

    public function add(string $jti, int $ttl): void
    {
        $this->client()->setex($this->key($jti), max(1, $ttl), '1');
    }

    public function has(string $jti): bool
    {
        return (bool) $this->client()->exists($this->key($jti));
    }

    public function remove(string $jti): void
    {
        $this->client()->del($this->key($jti));
    }

    public function clear(): void
    {
        $keys = $this->client()->keys($this->prefix . '*');
        if ($keys) {
            $this->client()->del(...$keys);
        }
    }

    private function key(string $jti): string
    {
        return $this->prefix . $jti;
    }

    /**
     * @return \Redis
     */
    private function client()
    {
        if ($this->client === null) {
            $redis = new \Redis();
            $connected = $redis->connect(
                (string) ($this->config['host'] ?? '127.0.0.1'),
                (int) ($this->config['port'] ?? 6379),
                (float) ($this->config['timeout'] ?? 0.0)
            );
            if (!$connected) {
                throw new JwtException('Unable to connect to Redis for JWT blacklist.');
            }
            if (!empty($this->config['password'])) {
                $redis->auth((string) $this->config['password']);
            }
            if (isset($this->config['database'])) {
                $redis->select((int) $this->config['database']);
            }
            $this->client = $redis;
        }
        return $this->client;
    }
}
