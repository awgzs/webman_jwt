<?php

declare(strict_types=1);

require __DIR__ . '/../vendor/autoload.php';

use Melo\Jwt\Exception\TokenBlacklistedException;
use Melo\Jwt\Exception\TokenExpiredException;
use Melo\Jwt\Exception\TokenInvalidException;
use Melo\Jwt\Facade;
use Melo\Jwt\JwtManager;

$pass = 0;
$fail = 0;

// v7 起 HMAC 密钥长度需 >= 算法摘要长度：HS256>=32、HS384>=48、HS512>=64 字节
const TEST_SECRET = 'test-secret-key-0123456789abcdef0123456789abcdef'; // 48 字节
const ADMIN_SECRET = 'admin-secret-0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef'; // 80 字节

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

function config(array $overrides = []): array
{
    $base = require __DIR__ . '/../config/melo-jwt.php';
    $base['guards']['default'] = array_merge($base['guards']['default'], $overrides);
    return $base;
}

echo "\n== 统一签发（默认双令牌） ==\n";
$jwt = (new JwtManager(config(['secret' => TEST_SECRET])))->guard();
$tokens = $jwt->encode(['uid' => 1001, 'name' => 'melo']);
$token = $tokens['access_token'];
check('encode 默认返回双令牌', isset($tokens['access_token'], $tokens['refresh_token'], $tokens['token_type'], $tokens['expires_in']));
check('access token 为三段式', substr_count($token, '.') === 2);
check('refresh token 为三段式且不同', substr_count($tokens['refresh_token'], '.') === 2 && $tokens['refresh_token'] !== $token);
check('access token 可 verify', $jwt->verify($token));
check('refresh token 可 decodeRefresh', ($jwt->decodeRefresh($tokens['refresh_token'])['uid'] ?? null) === 1001);
$claims = $jwt->decode($token);
check('decode 拿到自定义声明', ($claims['uid'] ?? null) === 1001 && ($claims['name'] ?? null) === 'melo');
check('自动写入 iat/exp', isset($claims['iat'], $claims['exp']));
check('claims() 不验签解析', ($jwt->claims($token)['uid'] ?? null) === 1001);

echo "\n== 异常处理 ==\n";
$tampered = substr($token, 0, -3) . 'aaa';
check('篡改签名 -> TokenInvalidException', (function () use ($jwt, $tampered) {
    try { $jwt->decode($tampered); return false; } catch (TokenInvalidException) { return true; }
})());
$expiredJwt = (new JwtManager(config(['secret' => TEST_SECRET, 'ttl' => 1])))->guard();
$expiredToken = $expiredJwt->encode(['uid' => 1])['access_token'];
sleep(2); // 等待 token 真实过期
check('过期 token -> TokenExpiredException', (function () use ($expiredJwt, $expiredToken) {
    try { $expiredJwt->decode($expiredToken); return false; } catch (TokenExpiredException) { return true; }
})());

echo "\n== 刷新 ==\n";
$refreshed = $jwt->refresh($token);
check('refresh 生成新 token', $refreshed !== $token && $jwt->verify($refreshed));
check('refresh 保留声明', ($jwt->decode($refreshed)['uid'] ?? null) === 1001);
$refreshedExpired = $expiredJwt->refresh($expiredToken);
check('过期 token 可刷新', $expiredJwt->verify($refreshedExpired));

echo "\n== 黑名单 ==\n";
$cfg = config(['secret' => TEST_SECRET]);
$cfg['blacklist'] = ['enable' => true, 'driver' => 'array', 'prefix' => 'test:'];
$mgr = new JwtManager($cfg);
$blJwt = $mgr->guard();
$blToken = $blJwt->encode(['uid' => 7])['access_token'];
check('开启黑名单后写入 jti', isset($blJwt->decode($blToken)['jti']));
$blJwt->invalidate($blToken);
check('isBlacklisted 命中', $blJwt->isBlacklisted($blToken));
check('已撤销 token -> TokenBlacklistedException', (function () use ($blJwt, $blToken) {
    try { $blJwt->decode($blToken); return false; } catch (TokenBlacklistedException) { return true; }
})());

echo "\n== 多守卫 ==\n";
$multi = config(['secret' => TEST_SECRET]);
$multi['guards']['admin'] = [
    'algo' => 'HS512',
    'secret' => ADMIN_SECRET,
    'ttl' => 60,
    'refresh_secret' => 'admin-refresh-secret-0123456789abcdef0123456789abcdef0123456789abcdef',
];
$adminToken = (new JwtManager($multi))->guard('admin')->encode(['role' => 'admin'])['access_token'];
check('指定守卫签发/验证', (new JwtManager($multi))->guard('admin')->verify($adminToken));
check('不同守卫密钥隔离', !(new JwtManager($multi))->guard('default')->verify($adminToken));

echo "\n== 门面 / 大驼峰辅助函数 ==\n";
Facade::setManager(new JwtManager(config(['secret' => TEST_SECRET])));
$facadeTokens = Facade::encode(['uid' => 88]);
$facadeToken = $facadeTokens['access_token'];
check('门面 encode 返回双令牌', isset($facadeTokens['access_token'], $facadeTokens['refresh_token']));
check('门面静态方法转发', Facade::verify($facadeToken));
check('Jwt() 辅助函数', Jwt()->verify($facadeToken));
check('JwtToken()/JwtVerify() 辅助函数', JwtVerify(JwtToken(['uid' => 9])['access_token']));
check('旧 snake_case 辅助函数已移除', !function_exists('jwt_token') && !function_exists('jwt_login') && !function_exists('jwt_verify'));
check('门面未配置守卫抛异常', (function () {
    try { Facade::guard('nope'); return false; } catch (\Melo\Jwt\Exception\JwtException) { return true; }
})());

echo "\n结果: {$pass} passed, {$fail} failed\n";
exit($fail === 0 ? 0 : 1);
