<?php

declare(strict_types=1);

namespace Melo\Jwt\Exception;

/**
 * Token 无效（签名错误、格式错误、缺少必要声明等）
 */
class TokenInvalidException extends JwtException
{
}
