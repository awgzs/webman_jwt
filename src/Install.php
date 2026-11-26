<?php

declare(strict_types=1);

namespace Melo\Jwt;

/** webman 通过 WEBMAN_PLUGIN 常量发现本类，install 时自动复制配置模板。 */
class Install
{
    public const WEBMAN_PLUGIN = true;

    /** @var array<string, string> 源相对 src/，目标相对 base_path() */
    protected static array $pathRelation = [
        'config/plugin/melo/jwt' => 'config/plugin/melo/jwt',
    ];

    public static function install(): void
    {
        static::installByRelation();
    }

    public static function uninstall(): void
    {
        static::uninstallByRelation();
    }

    public static function installByRelation(): void
    {
        foreach (static::$pathRelation as $source => $dest) {
            $pos = strrpos($dest, '/');
            if ($pos !== false) {
                $parentDir = base_path() . '/' . substr($dest, 0, $pos);
                if (!is_dir($parentDir) && !@mkdir($parentDir, 0777, true) && !is_dir($parentDir)) {
                    continue;
                }
            }

            // copy_dir 第三参数 $overwrite 默认 false，保留用户对配置的修改
            copy_dir(__DIR__ . '/' . $source, base_path() . '/' . $dest);
        }
    }

    public static function uninstallByRelation(): void
    {
        foreach (static::$pathRelation as $source => $dest) {
            $path = base_path() . '/' . $dest;
            if (!is_dir($path) && !is_file($path)) {
                continue;
            }
            remove_dir($path);
        }
    }
}
