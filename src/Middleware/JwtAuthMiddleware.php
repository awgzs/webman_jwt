<?php

declare(strict_types=1);

namespace Melo\Jwt\Middleware;

use Melo\Jwt\Exception\JwtException;
use Melo\Jwt\Exception\TokenMissingException;
use Melo\Jwt\Facade;
use Webman\Http\Request;
use Webman\Http\Response;
use Closure;

/**
 * JWT 认证中间件。
 *
 * 在 config/middleware.php 中注册：
 *   '' => [ \Melo\Jwt\Middleware\JwtAuthMiddleware::class ],
 *
 * 认证成功后，claims 会写入请求上下文：
 *   - $request->jwtClaims = [...]
 *   - context('jwt.claims', [...])（Webman 协程上下文）
 */
class JwtAuthMiddleware
{
    public function process(Request $request, Closure $next): Response
    {
        $config = $this->config();

        // 插件关闭或路径命中白名单，直接放行
        if (empty($config['enable']) || $this->isWhitelisted($request->path(), $config['whitelist'] ?? [])) {
            return $next($request);
        }

        try {
            $token = $this->extractToken($request, $config['token'] ?? []);
            if ($token === null || $token === '') {
                throw new TokenMissingException('Authorization token is required.');
            }

            $claims = Facade::guard($this->guardName($config))->decode($token);
        } catch (JwtException $e) {
            return $this->fail($config, $e->getMessage());
        }

        // 注入请求上下文，业务层可直接使用
        $request->jwtClaims = $claims;
        if (function_exists('context')) {
            context('jwt.claims', $claims);
            context('jwt.token', $token ?? null);
        }

        return $next($request);
    }

    /**
     * 提取 token：优先取请求对象上显式传入的 token，其次取请求头。
     *
     * 显式传入方式：$request->withAttr('jwtToken', '<token>')，
     * 适用于非标准入口或上游已解析出 token 的场景。
     * 请求头默认格式：Authorization: Bearer <token>
     */
    private function extractToken(Request $request, array $tokenConfig): ?string
    {
        // 1) 显式传入的 token
        $passed = $request->jwtToken ?? null;
        if (is_string($passed) && $passed !== '') {
            return trim($passed);
        }

        // 2) 请求头
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
            // 请求头存在但前缀不匹配，视为无效
            return null;
        }

        return trim($value);
    }

    /**
     * 路径白名单匹配：支持完整路径与以 * 结尾的前缀
     */
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

    private function guardName(array $config): ?string
    {
        $guard = $config['guard'] ?? null;
        return is_string($guard) && $guard !== '' ? $guard : null;
    }

    /**
     * 构造统一的 401 响应
     */
    private function fail(array $config, string $message): Response
    {
        $exceptionConfig = $config['exception'] ?? [];
        $status = (int) ($exceptionConfig['status'] ?? 401);

        if (!empty($exceptionConfig['log']) && function_exists('Log')) {
            \support\Log::warning('[melo-jwt] ' . $message);
        }

        $body = $exceptionConfig['response'] ?? [
            'code' => $status,
            'message' => '{message}',
            'data' => null,
        ];
        $body = is_array($body) ? $body : [];
        $body['message'] = str_replace('{message}', $message, (string) ($body['message'] ?? '{message}'));

        return json($body, $status);
    }

    private function config(): array
    {
        if (function_exists('config')) {
            $config = config('melo-jwt');
            if (is_array($config)) {
                return $config;
            }
        }
        return [];
    }
}
