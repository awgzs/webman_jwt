<?php

declare(strict_types=1);

namespace Melo\Jwt;

use Melo\Jwt\Exception\JwtException;

final class ConfigLoader
{
    private const ACCESS_PLACEHOLDER = '__MELO_JWT_ACCESS_SECRET__';
    private const REFRESH_PLACEHOLDER = '__MELO_JWT_REFRESH_SECRET__';

    /** @var array<string, string> 进程内缓存，避免同一进程重复生成秘钥 */
    private static array $generated = [];

    public static function load(): array
    {
        $config = self::read();
        return self::resolveSecrets($config);
    }

    private static function read(): array
    {
        if (function_exists('config')) {
            $config = config('plugin.melo.jwt.app');
            if (is_array($config) && $config !== []) {
                return $config;
            }
        }

        $file = __DIR__ . '/config/plugin/melo/jwt/app.php';
        if (is_file($file)) {
            $config = require $file;
            if (is_array($config)) {
                return $config;
            }
        }

        return [];
    }

    private static function resolveSecrets(array $config): array
    {
        $jwt = $config['jwt'] ?? [];
        if (!is_array($jwt)) {
            $jwt = [];
        }

        $access = $jwt['access_secret_key'] ?? null;
        $refresh = $jwt['refresh_secret_key'] ?? null;

        $needAccess = !is_string($access) || $access === '' || $access === self::ACCESS_PLACEHOLDER;
        $needRefresh = !is_string($refresh) || $refresh === '' || $refresh === self::REFRESH_PLACEHOLDER;

        if (!$needAccess && !$needRefresh) {
            return $config;
        }

        if (!isset(self::$generated['access'])) {
            self::$generated['access'] = self::generateSecret();
            self::$generated['refresh'] = self::generateSecret();
        }

        $generated = [
            self::ACCESS_PLACEHOLDER => self::$generated['access'],
            self::REFRESH_PLACEHOLDER => self::$generated['refresh'],
        ];

        self::persist($generated);

        if ($needAccess) {
            $jwt['access_secret_key'] = $generated[self::ACCESS_PLACEHOLDER];
        }
        if ($needRefresh) {
            $jwt['refresh_secret_key'] = $generated[self::REFRESH_PLACEHOLDER];
        }
        $config['jwt'] = $jwt;

        return $config;
    }

    private static function generateSecret(): string
    {
        try {
            return bin2hex(random_bytes(32));
        } catch (\Throwable $e) {
            throw new JwtException('Unable to generate JWT secret: ' . $e->getMessage(), 0, $e);
        }
    }

    /** 找不到应用配置路径时仅保留在内存中。 */
    private static function persist(array $replacements): void
    {
        $file = self::configFile();
        if ($file === null) {
            return;
        }

        if (!is_file($file)) {
            $dir = dirname($file);
            if (!is_dir($dir) && !@mkdir($dir, 0755, true) && !is_dir($dir)) {
                return;
            }
            $template = __DIR__ . '/config/plugin/melo/jwt/app.php';
            if (!is_file($template) || !copy($template, $file)) {
                return;
            }
        }

        if (!is_writable($file)) {
            return;
        }

        $content = file_get_contents($file);
        if (!is_string($content)) {
            return;
        }

        $updated = str_replace(array_keys($replacements), array_values($replacements), $content);
        if ($updated !== $content) {
            file_put_contents($file, $updated, LOCK_EX);
        }
    }

    private static function configFile(): ?string
    {
        if (function_exists('config_path')) {
            $path = config_path('plugin/melo/jwt/app.php');
            if (is_string($path)) {
                return $path;
            }
        }
        if (function_exists('base_path')) {
            return base_path('config/plugin/melo/jwt/app.php');
        }
        return null;
    }
}
