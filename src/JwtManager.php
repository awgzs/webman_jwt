<?php

declare(strict_types=1);

namespace Melo\Jwt;

use Melo\Jwt\Blacklist\ArrayBlacklist;
use Melo\Jwt\Blacklist\BlacklistInterface;
use Melo\Jwt\Blacklist\RedisBlacklist;
use Melo\Jwt\Exception\JwtException;
use Melo\Jwt\Sso\RedisSso;
use Melo\Jwt\Sso\SsoInterface;
use Melo\Jwt\Sso\ThinkOrmSso;

class JwtManager
{
    private array $config;
    private ?Jwt $instance = null;

    public function __construct(array $config)
    {
        $this->config = $config;
    }

    /** guard 参数仅为兼容保留，配置统一从 jwt 段读取。 */
    public function guard(?string $name = null): Jwt
    {
        if ($this->instance === null) {
            $this->instance = new Jwt(
                $this->config,
                $this->createBlacklist(),
                $this->createSso()
            );
        }
        return $this->instance;
    }

    public function forget(?string $name = null): void
    {
        $this->instance = null;
    }

    /** 支持点号访问；不传 key 返回全部配置。 */
    public function config(?string $key = null, mixed $default = null): mixed
    {
        if ($key === null) {
            return $this->config;
        }

        $value = $this->config;
        foreach (explode('.', $key) as $segment) {
            if (!is_array($value) || !array_key_exists($segment, $value)) {
                return $default;
            }
            $value = $value[$segment];
        }
        return $value;
    }

    public function setConfig(array $config): void
    {
        $this->config = $config;
        $this->instance = null;
    }

    private function createBlacklist(): ?BlacklistInterface
    {
        $config = $this->config['blacklist'] ?? [];
        if (empty($config['enable'])) {
            return null;
        }

        $driver = $config['driver'] ?? 'array';
        return match ($driver) {
            'array' => new ArrayBlacklist(),
            'redis' => new RedisBlacklist(
                $config['redis'] ?? [],
                (string) ($config['prefix'] ?? 'melo_jwt:blacklist:')
            ),
            default => throw new JwtException("Unsupported blacklist driver [{$driver}].", 401000),
        };
    }

    private function createSso(): ?SsoInterface
    {
        $jwt = $this->config['jwt'] ?? [];
        if (empty($jwt['is_single_device'])) {
            return null;
        }

        $driver = strtolower((string) ($jwt['sso_driver'] ?? 'redis'));
        return match ($driver) {
            'redis' => new RedisSso(
                ['host' => '127.0.0.1', 'port' => 6379] + (array) ($jwt['redis'] ?? []),
                (string) ($jwt['cache_token_pre'] ?? 'JWT:TOKEN:')
            ),
            'mysql', 'thinkorm' => new ThinkOrmSso(
                (string) ($jwt['sso_table'] ?? 'melo_jwt_sso'),
                (string) ($jwt['sso_connection'] ?? '')
            ),
            default => throw new JwtException("Unsupported sso driver [{$driver}].", 401000),
        };
    }
}
