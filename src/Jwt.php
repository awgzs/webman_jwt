<?php

declare(strict_types=1);

namespace Melo\Jwt;

use Firebase\JWT\BeforeValidException;
use Firebase\JWT\ExpiredException;
use Firebase\JWT\JWT as FirebaseJwt;
use Firebase\JWT\Key;
use Firebase\JWT\SignatureInvalidException;
use Melo\Jwt\Blacklist\BlacklistInterface;
use Melo\Jwt\Exception\JwtException;
use Melo\Jwt\Exception\TokenBlacklistedException;
use Melo\Jwt\Exception\TokenExpiredException;
use Melo\Jwt\Exception\TokenInvalidException;
use Melo\Jwt\Exception\TokenKickedException;
use Melo\Jwt\Exception\TokenMissingException;
use Melo\Jwt\Sso\SsoInterface;

/** 载荷：业务字段放 extend，标准字段 iss/aud/iat/nbf/exp/jti，type 区分令牌类型。 */
class Jwt
{
    public const ACCESS_TOKEN = 1;
    public const REFRESH_TOKEN = 2;

    private const TYPE_ACCESS = 'access';
    private const TYPE_REFRESH = 'refresh';

    private array $config;
    private ?BlacklistInterface $blacklist;
    private ?SsoInterface $sso;
    private string $idField;
    private string $clientField;

    public function __construct(array $config, ?BlacklistInterface $blacklist = null, ?SsoInterface $sso = null)
    {
        $this->config = $config;
        $this->blacklist = $blacklist;
        $this->sso = $sso;
        $this->idField = (string) $this->jwt('id_field', 'id');
        $this->clientField = (string) $this->jwt('client_field', 'client');
    }

    /**
     * @param array    $extend      业务字段（含 id / client 时纳入单设备登录）
     * @param int|null $accessExp   覆盖 access 有效期
     * @param int|null $refreshExp  覆盖 refresh 有效期
     * @return array{token_type: string, access_expires_in: int, access_token: string, refresh_token?: string, refresh_expires_in?: int}
     */
    public function encode(array $extend, ?int $accessExp = null, ?int $refreshExp = null): array
    {
        $jti = $this->generateJti();
        $accessExp = $accessExp ?? (int) $this->jwt('access_exp', 7200);
        $refreshExp = $refreshExp ?? (int) $this->jwt('refresh_exp', 604800);

        $tokens = [
            'token_type' => 'Bearer',
            'access_expires_in' => $accessExp,
            'access_token' => $this->issue($extend, $accessExp, $jti, self::TYPE_ACCESS),
        ];

        if (!$this->refreshDisabled()) {
            $tokens['refresh_token'] = $this->issue($extend, $refreshExp, $jti, self::TYPE_REFRESH);
            $tokens['refresh_expires_in'] = $refreshExp;
        }

        $this->registerSso($extend, $jti, max($accessExp, $refreshExp));

        return $this->mapResponseFields($tokens);
    }

    private function issue(array $extend, int $exp, string $jti, string $type): string
    {
        $now = time();
        $nbf = (int) $this->jwt('nbf', 0);

        $payload = [
            'iss' => $this->jwt('iss', 'melo-jwt'),
            'aud' => $this->jwt('aud', 'melo-jwt-client'),
            'iat' => $now,
            'nbf' => $now + $nbf,
            'exp' => $now + ($exp > 0 ? $exp : 315360000),
            'jti' => $jti,
            'type' => $type,
            'extend' => $extend,
        ];

        $leeway = (int) $this->jwt('leeway', 0);
        $previousLeeway = FirebaseJwt::$leeway;
        FirebaseJwt::$leeway = $leeway;

        try {
            return FirebaseJwt::encode($payload, $this->signingKey($type), $this->algo());
        } catch (\Throwable $e) {
            throw new JwtException('Failed to encode token: ' . $e->getMessage(), 0, $e);
        } finally {
            FirebaseJwt::$leeway = $previousLeeway;
        }
    }

    /** @return array{iss: string, aud: string, iat: int, nbf: int, exp: int, jti: string, type: string, extend: array} */
    public function verify(int $tokenType = self::ACCESS_TOKEN, ?string $token = null, bool $checkState = true): array
    {
        $token ??= $this->getTokenFromHeaders();

        try {
            $payload = $this->decodeRaw($token, $tokenType);
        } catch (TokenExpiredException $e) {
            throw $tokenType === self::REFRESH_TOKEN
                ? new TokenExpiredException('刷新令牌会话已过期，请再次登录！', 401023, $e)
                : new TokenExpiredException('身份验证会话已过期，请重新登录！', 401013, $e);
        } catch (SignatureInvalidException $e) {
            throw $tokenType === self::REFRESH_TOKEN
                ? new TokenInvalidException('刷新令牌无效', 401021, $e)
                : new TokenInvalidException('身份验证令牌无效', 401011, $e);
        } catch (BeforeValidException $e) {
            throw $tokenType === self::REFRESH_TOKEN
                ? new TokenInvalidException('刷新令牌尚未生效', 401022, $e)
                : new TokenInvalidException('身份验证令牌尚未生效', 401012, $e);
        } catch (TokenInvalidException $e) {
            throw $e;
        } catch (\Throwable $e) {
            throw $tokenType === self::REFRESH_TOKEN
                ? new TokenInvalidException('刷新令牌未知错误', 401025, $e)
                : new TokenInvalidException('访问令牌未知错误', 401015, $e);
        }

        $expectedType = $tokenType === self::REFRESH_TOKEN ? self::TYPE_REFRESH : self::TYPE_ACCESS;
        if (($payload['type'] ?? null) !== $expectedType) {
            throw $tokenType === self::REFRESH_TOKEN
                ? new TokenInvalidException('刷新令牌无效', 401021)
                : new TokenInvalidException('身份验证令牌无效', 401011);
        }

        if (!is_array($payload['extend'] ?? null)) {
            throw $tokenType === self::REFRESH_TOKEN
                ? new TokenInvalidException('刷新令牌获取的扩展字段不存在', 401024)
                : new TokenInvalidException('获取的扩展字段不存在', 401014);
        }

        if ($checkState) {
            $this->assertNotBlacklisted($payload);
            $this->assertSsoValid($payload);
        }

        return $payload;
    }

    /**
     * @param string|null $refreshToken 不传则从请求头获取
     * @param array       $extend       引用返回业务字段
     * @return array{token_type: string, access_expires_in: int, access_token: string, refresh_token?: string, refresh_expires_in?: int}
     */
    public function refreshToken(?string $refreshToken = null, array &$extend = []): array
    {
        $payload = $this->verify(self::REFRESH_TOKEN, $refreshToken);
        $extend = $payload['extend'];

        $jti = $this->generateJti();
        $accessExp = (int) ($extend['access_exp'] ?? $this->jwt('access_exp', 7200));
        $refreshExp = (int) ($extend['refresh_exp'] ?? $this->jwt('refresh_exp', 604800));

        $tokens = [
            'token_type' => 'Bearer',
            'access_expires_in' => $accessExp,
            'access_token' => $this->issue($extend, $accessExp, $jti, self::TYPE_ACCESS),
        ];

        if (!$this->refreshDisabled()) {
            $tokens['refresh_token'] = $this->issue($extend, $refreshExp, $jti, self::TYPE_REFRESH);
            $tokens['refresh_expires_in'] = $refreshExp;
        }

        $this->registerSso($extend, $jti, max($accessExp, $refreshExp));

        return $this->mapResponseFields($tokens);
    }

    /** 不传 client 则退出该用户全部设备。 */
    public function clear(string|int $userId, ?string $client = null): void
    {
        if ($this->sso === null) {
            throw new JwtException('Single device login is not enabled.', 401000);
        }

        if ($client === null) {
            $this->sso->logoutAll($userId);
            return;
        }

        if ($client === '') {
            throw new JwtException('Client type must not be empty.', 401000);
        }

        $this->sso->logout($userId, $client);
    }

    public function getExtend(?string $token = null): array
    {
        return (array) ($this->verify(self::ACCESS_TOKEN, $token)['extend'] ?? []);
    }

    public function getExtendVal(string $key, mixed $default = '', ?string $token = null): mixed
    {
        return $this->getExtend($token)[$key] ?? $default;
    }

    public function getCurrentId(?string $token = null): int|string
    {
        $id = $this->getExtendVal($this->idField, '', $token);
        return (is_int($id) || is_string($id)) ? $id : 0;
    }

    public function getTokenExp(int $tokenType = self::ACCESS_TOKEN, ?string $token = null): int
    {
        return (int) ($this->verify($tokenType, $token)['exp'] ?? 0) - time();
    }

    public function getUser(?string $token = null): mixed
    {
        $userModel = $this->jwt('user_model');
        return is_callable($userModel) ? $userModel($this->getCurrentId($token)) : [];
    }

    public function verifyTokenSafe(string $token, int $tokenType = self::ACCESS_TOKEN): bool
    {
        try {
            $this->verify($tokenType, $token);
            return true;
        } catch (\Throwable) {
            return false;
        }
    }

    /** 只解析载荷不验签，勿用于鉴权。 */
    public function claims(string $token): array
    {
        $parts = explode('.', $token);
        if (count($parts) !== 3 || $parts[1] === '') {
            throw new TokenInvalidException('Malformed token.', 401001);
        }

        $payload = json_decode(FirebaseJwt::urlsafeB64Decode($parts[1]), true);
        if (!is_array($payload)) {
            throw new TokenInvalidException('Invalid token payload.', 401001);
        }
        return $payload;
    }

    /** 需开启黑名单。 */
    public function invalidate(string $token): void
    {
        if ($this->blacklist === null) {
            throw new JwtException('Blacklist is not enabled.', 401015);
        }

        $payload = $this->claims($token);
        $jti = (string) ($payload['jti'] ?? '');
        if ($jti === '') {
            throw new TokenInvalidException('Token does not contain a jti claim.', 401011);
        }

        $ttl = (int) ($payload['exp'] ?? 0) - time();
        if ($ttl > 0) {
            $this->blacklist->add($jti, $ttl);
        }
    }

    public function isBlacklisted(string $token): bool
    {
        if ($this->blacklist === null) {
            return false;
        }
        $payload = $this->claims($token);
        return isset($payload['jti']) && $this->blacklist->has((string) $payload['jti']);
    }

    public function getBlacklist(): ?BlacklistInterface
    {
        return $this->blacklist;
    }

    public function setBlacklist(?BlacklistInterface $blacklist): void
    {
        $this->blacklist = $blacklist;
    }

    public function getSso(): ?SsoInterface
    {
        return $this->sso;
    }

    public function setSso(?SsoInterface $sso): void
    {
        $this->sso = $sso;
    }

    /** 支持配置是否允许 GET 参数兜底。 */
    private function getTokenFromHeaders(): string
    {
        if (!function_exists('request')) {
            throw new TokenMissingException('请求未携带 authorization 信息', 401000);
        }

        $request = request();
        $authorization = $request->header('authorization', '');
        if (!is_string($authorization) || $authorization === '' || $authorization === 'undefined') {
            if (!$this->jwt('is_support_get_token', false)) {
                throw new TokenMissingException('请求未携带authorization信息', 401000);
            }
            $authorization = $request->get((string) $this->jwt('is_support_get_token_key', 'authorization'), '');
            if (!is_string($authorization) || $authorization === '') {
                throw new TokenMissingException('请求未携带authorization信息', 401000);
            }
            $authorization = 'Bearer ' . $authorization;
        }

        if (2 !== count(explode(' ', $authorization))) {
            throw new TokenInvalidException('Bearer验证中的凭证格式有误，中间必须有个空格', 401000);
        }

        [$type, $token] = explode(' ', $authorization);
        if ('Bearer' !== $type) {
            throw new TokenInvalidException('接口认证方式需为Bearer', 401000);
        }
        if ($token === '' || $token === 'undefined') {
            throw new TokenInvalidException('尝试获取的Authorization信息不存在', 401000);
        }

        return $token;
    }

    private function decodeRaw(string $token, int $tokenType): array
    {
        $leeway = (int) $this->jwt('leeway', 0);
        $previousLeeway = FirebaseJwt::$leeway;
        FirebaseJwt::$leeway = $leeway;

        try {
            $decoded = FirebaseJwt::decode($token, new Key($this->verificationKey($tokenType), $this->algo()));
            // 递归转换为关联数组，确保嵌套的 extend 也是 array
            return (array) json_decode(
                json_encode($decoded, flags: JSON_THROW_ON_ERROR),
                true,
                flags: JSON_THROW_ON_ERROR
            );
        } catch (ExpiredException $e) {
            throw new TokenExpiredException('Token has expired.', 0, $e);
        } catch (SignatureInvalidException $e) {
            throw $e;
        } catch (BeforeValidException $e) {
            throw $e;
        } catch (\Throwable $e) {
            throw new TokenInvalidException('Token is invalid: ' . $e->getMessage(), 0, $e);
        } finally {
            FirebaseJwt::$leeway = $previousLeeway;
        }
    }

    private function assertNotBlacklisted(array $payload): void
    {
        if ($this->blacklist !== null && isset($payload['jti']) && $this->blacklist->has((string) $payload['jti'])) {
            throw new TokenBlacklistedException('Token has been revoked.', 401015);
        }
    }

    private function assertSsoValid(array $payload): void
    {
        if ($this->sso === null || !$this->jwt('is_single_device', false)) {
            return;
        }

        $extend = (array) ($payload['extend'] ?? []);
        if (!isset($extend[$this->idField], $extend[$this->clientField])) {
            return;
        }

        $userId = (string) $extend[$this->idField];
        $client = (string) $extend[$this->clientField];
        $currentJti = $this->sso->get($userId, $client);
        $tokenJti = (string) ($payload['jti'] ?? '');

        if ($currentJti === null || $tokenJti === '' || !hash_equals($currentJti, $tokenJti)) {
            throw new TokenKickedException('该账号已在其他设备登录，强制下线', 401015);
        }
    }

    private function registerSso(array $extend, string $jti, int $ttl): void
    {
        if ($this->sso === null || !$this->jwt('is_single_device', false)) {
            return;
        }
        if (!isset($extend[$this->idField], $extend[$this->clientField])) {
            return;
        }

        $ttl = $ttl > 0 ? $ttl + (int) $this->jwt('leeway', 0) : 315360000;
        $this->sso->store(
            (string) $extend[$this->idField],
            (string) $extend[$this->clientField],
            $jti,
            $ttl
        );
    }

    private function algo(): string
    {
        return strtoupper((string) $this->jwt('algorithms', 'HS256'));
    }

    private function refreshDisabled(): bool
    {
        return (bool) $this->jwt('refresh_disable', false);
    }

    private function signingKey(string $type): string
    {
        $hmac = str_starts_with($this->algo(), 'HS');
        return $this->resolveKey(
            $type === self::TYPE_REFRESH
                ? ($hmac ? 'refresh_secret_key' : 'refresh_private_key')
                : ($hmac ? 'access_secret_key' : 'access_private_key')
        );
    }

    private function verificationKey(int $tokenType): string
    {
        $hmac = str_starts_with($this->algo(), 'HS');
        return $this->resolveKey(
            $tokenType === self::REFRESH_TOKEN
                ? ($hmac ? 'refresh_secret_key' : 'refresh_public_key')
                : ($hmac ? 'access_secret_key' : 'access_public_key')
        );
    }

    private function resolveKey(string $key): string
    {
        $value = $this->jwt($key);
        if ($value === null || $value === '') {
            throw new JwtException("Missing [{$key}] in config/plugin/melo/jwt/app.php.", 401000);
        }

        $value = (string) $value;
        if (!str_contains($value, '-----BEGIN') && is_file($value)) {
            $content = file_get_contents($value);
            if ($content === false) {
                throw new JwtException("Unable to read key file: {$value}", 401000);
            }
            return $content;
        }
        return $value;
    }

    private function jwt(string $key, mixed $default = null): mixed
    {
        return $this->config['jwt'][$key] ?? $default;
    }

    /** 按 response_fields 映射签发结果的字段名，未列出的键保持原样。 */
    private function mapResponseFields(array $tokens): array
    {
        $map = $this->config['response_fields'] ?? [];
        if (!is_array($map) || $map === []) {
            return $tokens;
        }

        $mapped = [];
        foreach ($tokens as $key => $value) {
            $name = $map[$key] ?? $key;
            $mapped[is_string($name) && $name !== '' ? $name : $key] = $value;
        }
        return $mapped;
    }

    private function generateJti(): string
    {
        return bin2hex(random_bytes(16));
    }
}
