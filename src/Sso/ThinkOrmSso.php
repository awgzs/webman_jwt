<?php

declare(strict_types=1);

namespace Melo\Jwt\Sso;

use Melo\Jwt\Exception\JwtException;

/** 依赖可选的 topthink/think-orm，表结构见 README。 */
class ThinkOrmSso implements SsoInterface
{
    private string $table;
    private string $connection;

    public function __construct(string $table = 'melo_jwt_sso', string $connection = '')
    {
        if (!class_exists('think\\facade\\Db')) {
            throw new JwtException('topthink/think-orm is required for the mysql sso driver. Run: composer require topthink/think-orm');
        }
        $this->table = $table;
        $this->connection = $connection;
    }

    public function store(string|int $userId, string $deviceType, string $jti, int $ttl): void
    {
        $row = $this->db()
            ->where('user_id', (string) $userId)
            ->where('device_type', $deviceType)
            ->find();

        $now = time();
        $data = [
            'user_id' => (string) $userId,
            'device_type' => $deviceType,
            'jti' => $jti,
            'expire_time' => $now + $ttl,
            'update_time' => $now,
        ];

        if ($row) {
            $this->db()
                ->where('user_id', (string) $userId)
                ->where('device_type', $deviceType)
                ->update($data);
        } else {
            $data['create_time'] = $now;
            $this->db()->insert($data);
        }
    }

    public function get(string|int $userId, string $deviceType): ?string
    {
        $row = $this->db()
            ->where('user_id', (string) $userId)
            ->where('device_type', $deviceType)
            ->where('expire_time', '>', time())
            ->find();

        return $row ? (string) ($row['jti'] ?? '') : null;
    }

    public function logout(string|int $userId, string $deviceType): void
    {
        $this->db()
            ->where('user_id', (string) $userId)
            ->where('device_type', $deviceType)
            ->delete();
    }

    public function logoutAll(string|int $userId): void
    {
        $this->db()
            ->where('user_id', (string) $userId)
            ->delete();
    }

    /**
     * @return \think\db\Query
     */
    private function db()
    {
        $db = \think\facade\Db::class;
        $query = $this->connection !== '' ? $db::connect($this->connection) : $db::connect();
        return $query->table($this->table);
    }
}
