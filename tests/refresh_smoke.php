<?php

declare(strict_types=1);

require __DIR__ . '/../vendor/autoload.php';

use Melo\Jwt\Exception\JwtException;
use Melo\Jwt\Exception\TokenInvalidException;
use Melo\Jwt\Exception\TokenKickedException;
use Melo\Jwt\JwtManager;
use Melo\Jwt\Sso\SsoInterface;

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

class ArraySso implements SsoInterface
{
    public array $data = [];
    private function key(string|int $u, string $d): string { return $u . '|' . $d; }
    public function store(string|int $u, string $d, string $jti, int $ttl): void { $this->data[$this->key($u, $d)] = $jti; }
    public function get(string|int $u, string $d): ?string { return $this->data[$this->key($u, $d)] ?? null; }
    public function logout(string|int $u, string $d): void { unset($this->data[$this->key($u, $d)]); }
    public function logoutAll(string|int $u): void
    {
        foreach (array_keys($this->data) as $key) {
            if (str_starts_with($key, $u . '|')) { unset($this->data[$key]); }
        }
    }
}

$base = require __DIR__ . '/../config/melo-jwt.php';
$base['guards']['default']['secret'] = 'access-secret-0123456789abcdef0123456789abcdef';
$base['guards']['default']['refresh_secret'] = 'refresh-secret-0123456789abcdef0123456789abcdef';
$base['guards']['default']['ttl'] = 3600;
$base['guards']['default']['refresh_ttl'] = 1209600;
$base['blacklist']['enable'] = false;
$base['sso']['enable'] = true;
$base['refresh']['rotate'] = true;

$sso = new ArraySso();
$manager = new JwtManager($base);
$jwt = $manager->guard();
$jwt->setSso($sso);

echo "\n== 统一签发双令牌 ==\n";
$tokens = $jwt->encode(['uid' => 1001, 'device' => 'ios', 'name' => 'melo']);
check('encode 返回 access/refresh 双令牌', isset($tokens['access_token'], $tokens['refresh_token']));
check('access token 可正常 decode', ($jwt->decode($tokens['access_token'])['uid'] ?? null) == 1001);
check('refresh token 可独立 decode', ($jwt->decodeRefresh($tokens['refresh_token'])['uid'] ?? null) == 1001);
check('access 与 refresh 是不同 token', $tokens['access_token'] !== $tokens['refresh_token']);

echo "\n== 独立密钥隔离 ==\n";
check('refresh token 不能用 access 密钥验证', !$jwt->verify($tokens['refresh_token']));
check('access token 不能用 refresh 密钥验证', (function () use ($jwt, $tokens) {
    try { $jwt->decodeRefresh($tokens['access_token']); return false; } catch (TokenInvalidException) { return true; }
})());

echo "\n== 类型防滥用 ==\n";
check('refresh token 不能当 access 使用', (function () use ($jwt, $tokens) {
    try { $jwt->decode($tokens['refresh_token']); return false; } catch (TokenInvalidException) { return true; }
})());

echo "\n== 刷新与轮换 ==\n";
$new = $jwt->refreshByToken($tokens['refresh_token']);
check('刷新返回新双令牌', isset($new['access_token'], $new['refresh_token']));
check('新 access token 有效', $jwt->verify($new['access_token']));
check('轮换后新 refresh token 有效', (function () use ($new, $jwt) { try { $jwt->decodeRefresh($new['refresh_token']); return true; } catch (\Throwable) { return false; } })());
check('轮换后旧 refresh token 失效（被踢）', (function () use ($jwt, $tokens) {
    try { $jwt->decodeRefresh($tokens['refresh_token']); return false; } catch (TokenKickedException) { return true; }
})());
check('轮换后旧 access token 失效（被踢）', !$jwt->verify($tokens['access_token']));
check('新 refresh 可再次刷新', (function () use ($new, $jwt) { try { $r = $jwt->refreshByToken($new["refresh_token"]); $jwt->decodeRefresh($r["refresh_token"]); return true; } catch (\Throwable) { return false; } })());

echo "\n== 关闭轮换 ==\n";
$noRotateJwt = (function () use ($base, $sso) {
    $cfg = $base;
    $cfg['refresh']['rotate'] = false;
    $m = new JwtManager($cfg);
    $j = $m->guard();
    $j->setSso($sso);
    return $j;
})();
$login2 = $noRotateJwt->encode(['uid' => 2002, 'device' => 'pc']);
$refreshed2 = $noRotateJwt->refreshByToken($login2['refresh_token']);
check('不轮换时 refresh token 保持不变', $refreshed2['refresh_token'] === $login2['refresh_token']);
check('不轮换时旧 refresh 仍可用', (function () use ($login2, $noRotateJwt) { try { $noRotateJwt->decodeRefresh($login2['refresh_token']); return true; } catch (\Throwable) { return false; } })());

echo "\n== 登出后 refresh 不可用 ==\n";
$noRotateJwt->logout(2002, 'pc');
check('登出后 refresh token 失效', (function () use ($noRotateJwt, $login2) {
    try { $noRotateJwt->refreshByToken($login2['refresh_token']); return false; } catch (TokenKickedException) { return true; }
})());

echo "\n== 单 token 旧刷新保持兼容 ==\n";
$plain = (new JwtManager($base))->guard();
$plainToken = $plain->encode(['uid' => 3003])['access_token'];
check('encode 仍可用', $plain->verify($plainToken));
check('refresh() 仍可用', $plain->verify($plain->refresh($plainToken)));

echo "\n== 缺少 refresh 密钥 ==\n";
check('未配 refresh_secret 时统一签发抛异常', (function () use ($base) {
    $cfg = $base;
    $cfg['guards']['default']['refresh_secret'] = null;
    $j = (new JwtManager($cfg))->guard();
    try { $j->encode(['uid' => 1]); return false; } catch (JwtException) { return true; }
})());

echo "\n结果: {$pass} passed, {$fail} failed\n";
exit($fail === 0 ? 0 : 1);
