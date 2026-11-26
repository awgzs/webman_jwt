<?php

declare(strict_types=1);

namespace Melo\Jwt\Middleware;

use Closure;
use Melo\Jwt\ConfigLoader;
use Melo\Jwt\Exception\JwtException;
use Melo\Jwt\Exception\TokenMissingException;
use Melo\Jwt\Jwt;
use Melo\Jwt\JwtToken;
use Webman\Http\Request;
use Webman\Http\Response;

/** 认证成功后载荷写入 $request->jwtClaims 与 context('jwt.claims')。 */
class JwtAuthMiddleware
{
    public function process(Request $request, Closure $next): Response
    {
        $config = $this->config();

        if (empty($config['enable']) || $this->isWhitelisted($request->path(), $config['whitelist'] ?? [])) {
            return $next($request);
        }

        try {
            $token = $this->extractToken($request, $config['token'] ?? []);
            if ($token === null || $token === '') {
                throw new TokenMissingException('请求未携带authorization信息', 401000);
            }

            $payload = JwtToken::verify(Jwt::ACCESS_TOKEN, $token);
        } catch (JwtException $e) {
            return $this->fail($config, $e->getMessage(), $e->getCode());
        }

        $request->jwtClaims = $payload;
        if (function_exists('context')) {
            context('jwt.claims', $payload);
            context('jwt.token', $token ?? null);
        }

        return $next($request);
    }

    /** 优先取请求对象上显式传入的 token，其次取请求头。 */
    private function extractToken(Request $request, array $tokenConfig): ?string
    {
        $passed = $request->jwtToken ?? null;
        if (is_string($passed) && $passed !== '') {
            return trim($passed);
        }

        $headerName = $tokenConfig['header'] ?? 'Authorization';
        $value = $request->header($headerName, '');
        if (!is_string($value) || $value === '') {
            return null;
        }

        $prefix = $tokenConfig['prefix'] ?? 'Bearer';
        if ($prefix !== '') {
            $prefixWithSpace = $prefix . ' ';
            if (stripos($value, $prefixWithSpace) === 0) {
                return trim(substr($value, strlen($prefixWithSpace)));
            }
            return null;
        }

        return trim($value);
    }

    /** 支持完整路径与以 * 结尾的前缀。 */
    private function isWhitelisted(string $path, array $whitelist): bool
    {
        foreach ($whitelist as $pattern) {
            if (!is_string($pattern) || $pattern === '') {
                continue;
            }
            if (str_ends_with($pattern, '*')) {
                if (str_starts_with($path, rtrim($pattern, '*'))) {
                    return true;
                }
            } elseif ($path === $pattern) {
                return true;
            }
        }
        return false;
    }

    private function fail(array $config, string $message, int $code = 0): Response
    {
        $exceptionConfig = $config['exception'] ?? [];
        $status = (int) ($exceptionConfig['status'] ?? 401);

        if (!empty($exceptionConfig['log']) && function_exists('Log')) {
            \support\Log::warning('[melo-jwt] ' . $message);
        }

        $body = $exceptionConfig['response'] ?? [
            'code' => $status,
            'msg' => '{msg}',
            'data' => null,
        ];
        $body = is_array($body) ? $body : [];
        if ($code > 0) {
            $body['code'] = $code;
        }
        $body['msg'] = str_replace('{msg}', $message, (string) ($body['msg'] ?? '{msg}'));

        return json($body, $status);
    }

    private function config(): array
    {
        return ConfigLoader::load();
    }
}
