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

/**
 * JWT 管理器：按配置创建并缓存各守卫实例。
 */
class JwtManager
{
    private array $config;

    /** @var array<string, Jwt> */
    private array $guards = [];

    public function __construct(array $config)
    {
        $this->config = $config;
    }

    /**
     * 获取指定守卫，不传则使用默认守卫。
     */
    public function guard(?string $name = null): Jwt
    {
        $name = $name ?: (string) ($this->config['default'] ?? 'default');

        if (!isset($this->guards[$name])) {
            $guardConfig = $this->config['guards'][$name] ?? null;
            if (!is_array($guardConfig)) {
                throw new JwtException("JWT guard [{$name}] is not configured.");
            }
            $ssoConfig = $this->config['sso'] ?? [];
            $ssoClaims = [
                'user' => (string) ($ssoConfig['user_claim'] ?? 'uid'),
                'device' => (string) ($ssoConfig['device_claim'] ?? 'device'),
            ];
            $refreshConfig = $this->config['refresh'] ?? [];
            $this->guards[$name] = new Jwt(
                $name,
                $guardConfig,
                $this->createBlacklist(),
                $this->createSso(),
                $ssoClaims,
                is_array($refreshConfig) ? $refreshConfig : []
            );
        }

        return $this->guards[$name];
    }

    /**
     * 移除缓存的守卫实例（修改配置后调用以强制重建）
     */
    public function forget(?string $name = null): void
    {
        if ($name === null) {
            $this->guards = [];
        } else {
            unset($this->guards[$name]);
        }
    }

    /**
     * 读取配置，支持点号访问；不传 key 返回全部配置。
     */
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
        $this->guards = [];
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
            default => throw new JwtException("Unsupported blacklist driver [{$driver}]."),
        };
    }

    private function createSso(): ?SsoInterface
    {
        $config = $this->config['sso'] ?? [];
        if (empty($config['enable'])) {
            return null;
        }

        $driver = strtolower((string) ($config['driver'] ?? 'redis'));
        return match ($driver) {
            'redis' => new RedisSso(
                $config['redis'] ?? [],
                (string) ($config['prefix'] ?? 'melo_jwt:sso:')
            ),
            'mysql', 'thinkorm' => new ThinkOrmSso(
                (string) ($config['table'] ?? 'melo_jwt_sso'),
                (string) ($config['connection'] ?? '')
            ),
            default => throw new JwtException("Unsupported sso driver [{$driver}]."),
        };
    }
}
