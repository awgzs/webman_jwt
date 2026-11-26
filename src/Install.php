<?php

declare(strict_types=1);

namespace Melo\Jwt;

/**
 * Webman 插件安装器。
 *
 * webman-framework 在 composer install/update 时通过 support\Plugin 扫描各包，
 * 发现含有 WEBMAN_PLUGIN 常量的 Install 类后自动调用 install()，
 * 把包内 src/config 下的配置模板复制到应用的 config 目录。
 *
 * 参照 webman/console 的 Install 实现。
 */
class Install
{
    public const WEBMAN_PLUGIN = true;

    /**
     * 源路径相对于本文件所在目录（src/），目标路径相对于应用根目录 base_path()。
     *
     * @var array<string, string>
     */
    protected static array $pathRelation = [
        'config/plugin/melo/jwt' => 'config/plugin/melo/jwt',
    ];

    /**
     * Install
     */
    public static function install(): void
    {
        static::installByRelation();
    }

    /**
     * Uninstall
     */
    public static function uninstall(): void
    {
        static::uninstallByRelation();
    }

    /**
     * 复制配置模板到应用配置目录。目标文件已存在时不覆盖，保护用户的修改。
     */
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

            // webman 自带的 copy_dir 第三参数 $overwrite 默认 false：
            // 目标文件已存在时保留，保护用户对配置做的修改。
            copy_dir(__DIR__ . '/' . $source, base_path() . '/' . $dest);
        }
    }

    /**
     * 卸载时移除本插件复制到应用的配置目录。
     */
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
