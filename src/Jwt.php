<?php

declare(strict_types=1);

namespace Melo\Jwt;

use Firebase\JWT\ExpiredException;
use Firebase\JWT\JWT as FirebaseJwt;
use Firebase\JWT\Key;
use Firebase\JWT\SignatureInvalidException;
use Firebase\JWT\BeforeValidException;
use Melo\Jwt\Blacklist\BlacklistInterface;
use Melo\Jwt\Exception\JwtException;
use Melo\Jwt\Exception\TokenBlacklistedException;
use Melo\Jwt\Exception\TokenExpiredException;
use Melo\Jwt\Exception\TokenInvalidException;
use Melo\Jwt\Exception\TokenKickedException;
use Melo\Jwt\Sso\SsoInterface;

/**
 * JWT 服务：统一签发（access + refresh）、验证、解析、刷新、撤销与单点登录。
 */
class Jwt
{
    private string $name;
    private array $config;
    private ?BlacklistInterface $blacklist;
    private ?SsoInterface $sso;

    /** @var array{user: string, device: string} SSO 用户/设备声明的字段名 */
    private array $ssoClaims;

    /** @var array{type_claim: string, type_value: string, rotate: bool} 双令牌配置 */
    private array $refreshConfig;

    public function __construct(
        string $name,
        array $config,
        ?BlacklistInterface $blacklist = null,
        ?SsoInterface $sso = null,
        ?array $ssoClaims = null,
        ?array $refreshConfig = null
    ) {
        $this->name = $name;
        $this->config = $config;
        $this->blacklist = $blacklist;
        $this->sso = $sso;
        $this->ssoClaims = $ssoClaims ?? ['user' => 'uid', 'device' => 'device'];
        $this->refreshConfig = $refreshConfig ?? [];
    }

    public function getName(): string
    {
        return $this->name;
    }

    public function getConfig(): array
    {
        return $this->config;
    }

    /**
     * 统一签发：一次调用返回 access token + refresh token（双令牌）。
     *
     * 开启 SSO 且 claims 中含 uid / device（声明名可配置）时，自动把本次 jti
     * 登记为 (userId, deviceType) 的当前登录态；同设备再次签发会挤掉旧令牌。
     * SSO 记录有效期取 refresh_ttl，保证 access 过期后 refresh 仍可正常使用。
     *
     * @param array       $claims 自定义声明（含 uid / device 时纳入 SSO）
     * @param int|null    $ttl    access 有效期（秒）；不传取配置，0 表示永不过期
     * @param string|null $jti    自定义 jti；不传自动生成，access 与 refresh 共用
     * @return array{access_token: string, refresh_token: string, token_type: string, expires_in: int}
     */
    public function encode(array $claims, ?int $ttl = null, ?string $jti = null): array
    {
        $jti = $jti ?? (string) ($claims['jti'] ?? $this->generateJti());

        $accessToken = $this->issue($claims, $ttl, $jti, 'access');
        $refreshToken = $this->issue($claims, null, $jti, 'refresh');

        $this->registerSso($claims, $jti, $this->ssoTtl());

        $expiresIn = $ttl ?? (int) ($this->config['ttl'] ?? 0);

        return [
            'access_token' => $accessToken,
            'refresh_token' => $refreshToken,
            'token_type' => 'Bearer',
            'expires_in' => $expiresIn,
        ];
    }

    /**
     * 底层签发逻辑：scope 决定使用哪套密钥与默认有效期
     */
    private function issue(array $claims, ?int $ttl, ?string $jti, string $scope): string
    {
        $now = time();
        $payload = array_merge($this->config['claims'] ?? [], $claims);

        $payload['iat'] = $payload['iat'] ?? $now;

        $ttl = $ttl ?? (int) ($this->config[$scope === 'refresh' ? 'refresh_ttl' : 'ttl'] ?? 0);
        if ($ttl > 0) {
            $payload['exp'] = $now + $ttl;
        } else {
            unset($payload['exp']);
        }

        $standard = ['iss' => 'issuer', 'aud' => 'audience', 'sub' => 'subject'];
        foreach ($standard as $claim => $configKey) {
            if (!array_key_exists($claim, $payload) && !empty($this->config[$configKey])) {
                $payload[$claim] = $this->config[$configKey];
            }
        }

        // 类型声明：区分 access / refresh，防止 refresh token 被当作 access token 使用
        $typeClaim = (string) ($this->refreshConfig['type_claim'] ?? 'type');
        $payload[$typeClaim] = $scope === 'refresh'
            ? (string) ($this->refreshConfig['type_value'] ?? 'refresh')
            : 'access';

        // 双令牌共用 jti（SSO 绑定与轮换取依赖），refresh token 始终携带
        if ($scope === 'refresh' || $this->blacklist !== null || $this->sso !== null || $jti !== null) {
            $payload['jti'] = $jti ?? ($payload['jti'] ?? $this->generateJti());
        }

        try {
            return FirebaseJwt::encode($payload, $this->signingKey($scope), $this->algo());
        } catch (\Throwable $e) {
            throw new JwtException('Failed to encode token: ' . $e->getMessage(), 0, $e);
        }
    }

    /**
     * 验证并解析 access token，返回声明数组
     *
     * @throws TokenExpiredException|TokenInvalidException|TokenBlacklistedException|TokenKickedException
     */
    public function decode(string $token, bool $checkState = true): array
    {
        $payload = $this->decodeRaw($token);

        // 防止 refresh token 被当作 access token 使用（即便密钥不同，这里再挡一层）
        $typeClaim = (string) ($this->refreshConfig['type_claim'] ?? 'type');
        if (($payload[$typeClaim] ?? 'access') === ($this->refreshConfig['type_value'] ?? 'refresh')) {
            throw new TokenInvalidException('Refresh token cannot be used as an access token.');
        }

        if (!empty($this->config['require_exp']) && !isset($payload['exp'])) {
            throw new TokenInvalidException('Token is missing the exp claim.');
        }

        if ($checkState) {
            $this->assertNotBlacklisted($payload);
            $this->assertSsoValid($payload);
        }

        return $payload;
    }

    /**
     * 验证并解析 refresh token（用独立密钥），返回声明数组
     *
     * @throws TokenInvalidException|TokenExpiredException|TokenKickedException
     */
    public function decodeRefresh(string $token): array
    {
        $payload = $this->decodeRaw($token, null, 'refresh');

        $typeClaim = (string) ($this->refreshConfig['type_claim'] ?? 'type');
        if (($payload[$typeClaim] ?? null) !== ($this->refreshConfig['type_value'] ?? 'refresh')) {
            throw new TokenInvalidException('Not a refresh token.');
        }

        if (!empty($this->config['require_exp']) && !isset($payload['exp'])) {
            throw new TokenInvalidException('Refresh token is missing the exp claim.');
        }

        $this->assertSsoValid($payload);

        return $payload;
    }

    /**
     * 仅校验 token 是否有效，不抛异常
     */
    public function verify(string $token): bool
    {
        try {
            $this->decode($token);
            return true;
        } catch (\Throwable) {
            return false;
        }
    }

    /**
     * 只解析载荷，不验证签名。
     * 仅用于读取 exp / jti 等非敏感字段，切勿用于鉴权判断。
     */
    public function claims(string $token): array
    {
        $parts = explode('.', $token);
        if (count($parts) !== 3 || $parts[1] === '') {
            throw new TokenInvalidException('Malformed token.');
        }

        $payload = json_decode(FirebaseJwt::urlsafeB64Decode($parts[1]), true);
        if (!is_array($payload)) {
            throw new TokenInvalidException('Invalid token payload.');
        }
        return $payload;
    }

    /**
     * 刷新 access token（单令牌旧接口，仍保持兼容）。
     * 原 token 即使已过期也可刷新（前提是签名有效）。
     * 启用 SSO 时会同步更新存储中的 jti，使旧 token 立即失效。
     *
     * @param int|null $ttl 新 token 的有效期；不传则沿用配置
     */
    public function refresh(string $token, ?int $ttl = null): string
    {
        // 先尝试常规解析；若已过期，则按需要放宽时钟容差重新解析（仍会校验签名）
        try {
            $payload = $this->decode($token);
        } catch (TokenExpiredException) {
            $exp = (int) ($this->claims($token)['exp'] ?? 0);
            $leeway = max(0, time() - $exp) + (int) ($this->config['leeway'] ?? 0) + 1;
            $payload = $this->decodeRaw($token, $leeway);
            $this->assertNotBlacklisted($payload);
        }

        unset($payload['iat'], $payload['exp'], $payload['nbf']);

        $ttl = $ttl ?? (int) ($this->config['ttl'] ?? 0);
        $jti = $this->generateJti();
        $newToken = $this->issue($payload, $ttl, $jti, 'access');

        $this->registerSso($payload, $jti, $this->ssoTtl());

        return $newToken;
    }

    /**
     * 用 refresh token 换取新令牌，支持轮换。
     *
     * 轮换（默认开启）：签发新的 access + refresh（共用新 jti），并更新 SSO，
     * 旧 refresh token 与旧 access token 立即失效。
     *
     * @param string      $refreshToken refresh token
     * @param int|null    $ttl          新 access token 有效期
     * @param bool|null   $rotate       是否轮换 refresh token；null 取配置
     * @return array{access_token: string, refresh_token: string, token_type: string, expires_in: int}
     */
    public function refreshByToken(string $refreshToken, ?int $ttl = null, ?bool $rotate = null): array
    {
        $payload = $this->decodeRefresh($refreshToken);

        $ttl = $ttl ?? (int) ($this->config['ttl'] ?? 0);
        $rotate = $rotate ?? (bool) ($this->refreshConfig['rotate'] ?? true);

        // 保留业务声明，剔除 token 自身元数据
        $claims = $payload;
        foreach (['iat', 'exp', 'nbf', 'jti', (string) ($this->refreshConfig['type_claim'] ?? 'type')] as $key) {
            unset($claims[$key]);
        }

        $jti = $rotate ? $this->generateJti() : (string) ($payload['jti'] ?? $this->generateJti());

        $accessToken = $this->issue($claims, $ttl, $jti, 'access');

        $refreshValue = $refreshToken;
        if ($rotate) {
            // 新 access 与 refresh 共享同一 jti，SSO 也更新为该 jti
            $refreshValue = $this->issue($claims, null, $jti, 'refresh');
        }
        $this->registerSso($claims, $jti, $this->ssoTtl());

        return [
            'access_token' => $accessToken,
            'refresh_token' => $refreshValue,
            'token_type' => 'Bearer',
            'expires_in' => $ttl,
        ];
    }

    /**
     * 登出：只需要用户ID。不传设备类型则退出该用户的全部设备。
     * 需要单独撤销某个 token 时使用 invalidate($token)。
     */
    public function logout(string|int $userId, ?string $deviceType = null): void
    {
        if ($this->sso === null) {
            throw new JwtException('SSO is not enabled for this guard.');
        }

        if ($deviceType === null) {
            $this->sso->logoutAll($userId);
            return;
        }

        if ($deviceType === '') {
            throw new JwtException('Device type must not be empty.');
        }

        $this->sso->logout($userId, $deviceType);
    }

    /**
     * 将 token 加入黑名单。过期时间取 token 剩余有效期。
     */
    public function invalidate(string $token): void
    {
        if ($this->blacklist === null) {
            throw new JwtException('Blacklist is not enabled for this guard.');
        }

        $payload = $this->claims($token);
        $jti = (string) ($payload['jti'] ?? '');
        if ($jti === '') {
            throw new TokenInvalidException('Token does not contain a jti claim.');
        }

        $exp = (int) ($payload['exp'] ?? 0);
        $ttl = $exp > 0 ? $exp - time() : (int) ($this->config['ttl'] ?? 0);
        if ($ttl > 0) {
            $this->blacklist->add($jti, $ttl);
        }
    }

    /**
     * 判断 token 是否已被撤销
     */
    public function isBlacklisted(string $token): bool
    {
        if ($this->blacklist === null) {
            return false;
        }
        $payload = $this->claims($token);
        return isset($payload['jti']) && $this->blacklist->has((string) $payload['jti']);
    }

    /**
     * 运行时替换黑名单存储
     */
    public function setBlacklist(?BlacklistInterface $blacklist): void
    {
        $this->blacklist = $blacklist;
    }

    public function getBlacklist(): ?BlacklistInterface
    {
        return $this->blacklist;
    }

    /**
     * 运行时替换 SSO 存储
     */
    public function setSso(?SsoInterface $sso): void
    {
        $this->sso = $sso;
    }

    public function getSso(): ?SsoInterface
    {
        return $this->sso;
    }

    private function decodeRaw(string $token, ?int $leewayOverride = null, string $scope = 'access'): array
    {
        $previousLeeway = FirebaseJwt::$leeway;
        FirebaseJwt::$leeway = $leewayOverride ?? (int) ($this->config['leeway'] ?? 0);

        try {
            $decoded = FirebaseJwt::decode($token, new Key($this->verificationKey($scope), $this->algo()));
            return (array) $decoded;
        } catch (ExpiredException $e) {
            throw new TokenExpiredException('Token has expired.', 0, $e);
        } catch (SignatureInvalidException $e) {
            throw new TokenInvalidException('Token signature is invalid.', 0, $e);
        } catch (BeforeValidException | \UnexpectedValueException | \DomainException | \InvalidArgumentException $e) {
            throw new TokenInvalidException('Token is invalid: ' . $e->getMessage(), 0, $e);
        } catch (\Throwable $e) {
            throw new JwtException('Failed to decode token: ' . $e->getMessage(), 0, $e);
        } finally {
            FirebaseJwt::$leeway = $previousLeeway;
        }
    }

    private function assertNotBlacklisted(array $payload): void
    {
        if ($this->blacklist !== null && isset($payload['jti']) && $this->blacklist->has((string) $payload['jti'])) {
            throw new TokenBlacklistedException('Token has been revoked.');
        }
    }

    /**
     * SSO 校验：仅对携带 uid/device 声明的 token 生效。
     * 存储中 jti 与 token 不一致或已不存在，说明该设备已被新登录挤下线或已登出。
     */
    private function assertSsoValid(array $payload): void
    {
        if ($this->sso === null) {
            return;
        }

        $userClaim = $this->ssoClaims['user'];
        $deviceClaim = $this->ssoClaims['device'];
        if (!isset($payload[$userClaim], $payload[$deviceClaim])) {
            // 未携带身份声明的 token，不受 SSO 约束
            return;
        }

        $userId = (string) $payload[$userClaim];
        $deviceType = (string) $payload[$deviceClaim];
        $currentJti = $this->sso->get($userId, $deviceType);
        $tokenJti = (string) ($payload['jti'] ?? '');

        if ($currentJti === null || $tokenJti === '' || !hash_equals($currentJti, $tokenJti)) {
            throw new TokenKickedException('Token has been replaced by a newer login or logged out.');
        }
    }

    /**
     * 若载荷含 SSO 身份信息，则登记当前 jti。
     */
    private function registerSso(array $payload, string $jti, int $ttl): void
    {
        if ($this->sso === null) {
            return;
        }

        $userClaim = $this->ssoClaims['user'];
        $deviceClaim = $this->ssoClaims['device'];
        if (!isset($payload[$userClaim], $payload[$deviceClaim])) {
            return;
        }

        $this->sso->store(
            (string) $payload[$userClaim],
            (string) $payload[$deviceClaim],
            $jti,
            $ttl > 0 ? $ttl : 315360000
        );
    }

    /**
     * SSO 登录态有效期：取 refresh_ttl，保证 access 过期后仍可刷新。
     */
    private function ssoTtl(): int
    {
        return (int) ($this->config['refresh_ttl'] ?? 315360000);
    }

    private function algo(): string
    {
        return strtoupper((string) ($this->config['algo'] ?? 'HS256'));
    }

    private function signingKey(string $scope = 'access'): string
    {
        $hmac = str_starts_with($this->algo(), 'HS');
        $configKey = $scope === 'refresh'
            ? ($hmac ? 'refresh_secret' : 'refresh_private_key')
            : ($hmac ? 'secret' : 'private_key');
        return $this->resolveKey($configKey);
    }

    private function verificationKey(string $scope = 'access'): string
    {
        $hmac = str_starts_with($this->algo(), 'HS');
        $configKey = $scope === 'refresh'
            ? ($hmac ? 'refresh_secret' : 'refresh_public_key')
            : ($hmac ? 'secret' : 'public_key');
        return $this->resolveKey($configKey);
    }

    private function resolveKey(string $configKey): string
    {
        $value = $this->config[$configKey] ?? null;
        if ($value === null || $value === '') {
            throw new JwtException("Missing [{$configKey}] for guard [{$this->name}].");
        }

        $value = (string) $value;
        // PEM 字符串直接返回；否则当作文件路径读取
        if (!str_contains($value, '-----BEGIN') && is_file($value)) {
            $content = file_get_contents($value);
            if ($content === false) {
                throw new JwtException("Unable to read key file: {$value}");
            }
            return $content;
        }
        return $value;
    }

    private function generateJti(): string
    {
        return bin2hex(random_bytes(16));
    }
}
