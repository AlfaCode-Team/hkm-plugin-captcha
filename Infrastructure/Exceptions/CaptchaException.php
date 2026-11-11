<?php

declare(strict_types=1);

namespace Plugins\Captcha\Infrastructure\Exceptions;

use AlfacodeTeam\PhpServicePlatform\Kernel\Exceptions\GatewayException;

/**
 * The plugin cannot verify at all — a missing secret, an unknown provider.
 *
 * A FAILED CHALLENGE IS NOT ONE OF THESE. That is a CaptchaVerdict, because a
 * bot being turned away is the system working, not an error, and raising on it
 * would route ordinary traffic through the ErrorPipeline and into whatever
 * notifier is wired to critical failures.
 *
 * Carries no secret and no token.
 */
final class CaptchaException extends GatewayException
{
    public static function notConfigured(string $detail): self
    {
        return new self("Captcha is not configured: {$detail}", layer: 'gateway.captcha');
    }
}
