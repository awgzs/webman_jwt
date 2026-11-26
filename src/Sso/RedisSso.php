<?php

declare(strict_types=1);

namespace Melo\Jwt\Sso;

use Melo\Jwt\Exception\JwtException;

/**
 * 基于 Redis 的单点登录存储。
 *
 * key 结构为 prefix + md5(userId) + ':' + md5(deviceType)，value 为当前有效 jti，
 * 通过 EXPIRE 自动过期。分段设计使 logoutAll 可按用户前缀 SCAN 并删除全部设备。
 */
class RedisSso implements SsoInterface
{
    private array $config;
    private string $prefix;
    /** @var \Redis|null */
    private $client = null;

    public function __construct(array $config = [], string $prefix = 'melo_jwt:sso:')
    {
        if (!extension_loaded('redis')) {
            throw new JwtException('The redis extension is required for the redis sso driver.');
        }
        $this->config = $config;
        $this->prefix = $prefix;
    }

    public function store(string|int $userId, string $deviceType, string $jti, int $ttl): void
    {
        $this->client()->setex($this->key($userId, $deviceType), max(1, $ttl), $jti);
    }

    public function get(string|int $userId, string $deviceType): ?string
    {
        $value = $this->client()->get($this->key($userId, $deviceType));
        return $value === false ? null : (string) $value;
    }

    public function logout(string|int $userId, string $deviceType): void
    {
        $this->client()->del($this->key($userId, $deviceType));
    }

    public function logoutAll(string|int $userId): void
    {
        $iterator = null;
        $pattern = $this->prefix . md5((string) $userId) . ':*';
        $client = $this->client();

        do {
            $keys = $client->scan($iterator, $pattern, 100);
            if (is_array($keys) && $keys !== []) {
                $client->del(...$keys);
            }
        } while ($iterator > 0);
    }

    private function key(string|int $userId, string $deviceType): string
    {
        return $this->prefix . md5((string) $userId) . ':' . md5($deviceType);
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
                throw new JwtException('Unable to connect to Redis for JWT SSO.');
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
