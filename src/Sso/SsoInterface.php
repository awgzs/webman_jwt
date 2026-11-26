<?php

declare(strict_types=1);

namespace Melo\Jwt\Sso;

/**
 * 单点登录存储接口。
 *
 * 以 (userId, deviceType) 为唯一键，同一用户在同一设备上只保留一个有效 jti。
 * 新签发覆盖旧 jti，旧 token 因此在校验时被判定为已下线。
 */
interface SsoInterface
{
    /**
     * 记录一次登录，覆盖同用户同设备的旧记录
     *
     * @param string|int $userId     用户标识（字符串或数字）
     * @param string     $deviceType 设备类型
     * @param string     $jti        token 唯一标识
     * @param int        $ttl        有效期（秒）
     */
    public function store(string|int $userId, string $deviceType, string $jti, int $ttl): void;

    /**
     * 读取同用户同设备当前有效的 jti；不存在或已过期返回 null
     */
    public function get(string|int $userId, string $deviceType): ?string;

    /**
     * 清除同用户同设备的登录记录
     */
    public function logout(string|int $userId, string $deviceType): void;

    /**
     * 清除指定用户的全部设备登录记录
     */
    public function logoutAll(string|int $userId): void;
}
