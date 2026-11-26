<?php

declare(strict_types=1);

require __DIR__ . '/../vendor/autoload.php';

use Melo\Jwt\Exception\JwtException;
use Melo\Jwt\Exception\TokenKickedException;
use Melo\Jwt\Exception\TokenMissingException;
use Melo\Jwt\JwtManager;
use Melo\Jwt\Sso\RedisSso;
use Melo\Jwt\Sso\SsoInterface;
use Melo\Jwt\Sso\ThinkOrmSso;

$pass = 0;
$fail = 0;

function check(string $name, bool $ok): void
{
    global $pass, $fail;
    if ($ok) {
        $pass++;
        echo "  PASS  {$name}\n";
    } else {
        $fail++;
        echo "  FAIL  {$name}\n";
    }
}

/** 内存版 SSO 存储测试桩 */
class ArraySso implements SsoInterface
{
    public array $data = [];

    private function key(string|int $userId, string $deviceType): string
    {
        return $userId . '|' . $deviceType;
    }

    public function store(string|int $userId, string $deviceType, string $jti, int $ttl): void
    {
        $this->data[$this->key($userId, $deviceType)] = $jti;
    }

    public function get(string|int $userId, string $deviceType): ?string
    {
        return $this->data[$this->key($userId, $deviceType)] ?? null;
    }

    public function logout(string|int $userId, string $deviceType): void
    {
        unset($this->data[$this->key($userId, $deviceType)]);
    }

    public function logoutAll(string|int $userId): void
    {
        foreach (array_keys($this->data) as $key) {
            if (str_starts_with($key, $userId . '|')) {
                unset($this->data[$key]);
            }
        }
    }
}

$base = require __DIR__ . '/../config/melo-jwt.php';
$base['guards']['default']['secret'] = 'sso-test-secret-0123456789abcdef0123456789abcdef';
$base['blacklist']['enable'] = false;
$base['sso']['enable'] = true;

$sso = new ArraySso();
$manager = new JwtManager($base);
$jwt = $manager->guard();
$jwt->setSso($sso);

echo "\n== 统一签发 + 单点登录核心逻辑 ==\n";

$token1 = $jwt->encode(['uid' => 1001, 'device' => 'ios', 'name' => 'first'])['access_token'];
$claims1 = $jwt->decode($token1);
check('encode 含 uid/device 时自动绑定 SSO', ($claims1['uid'] ?? null) == 1001 && ($claims1['device'] ?? null) === 'ios');
check('签发同时返回 refresh token', isset($jwt->encode(['uid' => 1001, 'device' => 'ios'])['refresh_token']));
check('字符串用户ID可用', $jwt->verify($jwt->encode(['uid' => 'user-abc', 'device' => 'web'])['access_token']));

$token2 = $jwt->encode(['uid' => 1001, 'device' => 'ios', 'name' => 'second'])['access_token'];
check('同设备新签发的 token 有效', $jwt->verify($token2));
check('同用户同设备旧 token 被挤下线', !$jwt->verify($token1));
check('被挤下线抛 TokenKickedException', (function () use ($jwt, $token1) {
    try { $jwt->decode($token1); return false; } catch (TokenKickedException) { return true; }
})());

$pcToken = $jwt->encode(['uid' => 1001, 'device' => 'pc'])['access_token'];
check('同用户不同设备互不影响', $jwt->verify($token2) && $jwt->verify($pcToken));

$otherUserToken = $jwt->encode(['uid' => 2002, 'device' => 'ios'])['access_token'];
check('不同用户同设备互不影响', $jwt->verify($token2) && $jwt->verify($otherUserToken));

echo "\n== 刷新与登出 ==\n";
$refreshed = $jwt->refresh($token2);
check('refresh 新 token 有效', $jwt->verify($refreshed));
check('refresh 后旧 token 失效', !$jwt->verify($token2));
check('refresh 保留 uid/device', ($jwt->decode($refreshed)['device'] ?? null) === 'ios');

$jwt->logout(1001, 'ios');
check('按设备登出后该设备 token 失效', !$jwt->verify($refreshed));
check('按设备登出不影响其他设备', $jwt->verify($pcToken));
check('按设备登出清理 SSO 记录', $sso->get(1001, 'ios') === null);

$jwt->logout(1001);
check('不传设备退出全部设备', !$jwt->verify($pcToken));
check('退出全部设备不影响其他用户', $jwt->verify($otherUserToken));
check('退出全部设备清空该用户记录', $sso->get(1001, 'pc') === null);

echo "\n== 与普通签发的兼容 ==\n";
$plain = $jwt->encode(['uid' => 9999])['access_token'];
check('不带 device 的 encode 不受 SSO 约束', $jwt->verify($plain));

echo "\n== 驱动构造守卫 ==\n";
check('RedisSso 可构造（redis 扩展可用）', (new RedisSso([], 'test:sso:')) instanceof RedisSso);
check('ThinkOrmSso 缺依赖时抛友好 JwtException', (function () {
    try { new ThinkOrmSso(); return false; } catch (JwtException $e) {
        return str_contains($e->getMessage(), 'think-orm');
    }
})());
check('未开启 SSO 时 logout 抛 JwtException', (function () use ($base) {
    $cfg = $base;
    $cfg['sso']['enable'] = false;
    $j = (new JwtManager($cfg))->guard();
    try { $j->logout(1001); return false; } catch (JwtException) { return true; }
})());
check('TokenMissingException 继承 JwtException', is_subclass_of(TokenMissingException::class, JwtException::class));

echo "\n结果: {$pass} passed, {$fail} failed\n";
exit($fail === 0 ? 0 : 1);
