<?php

declare(strict_types=1);

namespace Melo\Jwt\Exception;

/**
 * Token 已被同用户同设备的更新登录挤下线
 */
class TokenKickedException extends JwtException
{
}
