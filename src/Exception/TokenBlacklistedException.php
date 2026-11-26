<?php

declare(strict_types=1);

namespace Melo\Jwt\Exception;

/**
 * Token 已被撤销（命中黑名单）
 */
class TokenBlacklistedException extends JwtException
{
}
