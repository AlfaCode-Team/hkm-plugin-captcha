<?php

declare(strict_types=1);

namespace Plugins\Captcha\Infrastructure\Gateways;

use Plugins\Captcha\Domain\Contracts\CaptchaProvider;
use Plugins\Captcha\Domain\CaptchaVerdict;

/**
 * Verification turned off: everything passes.
 *
 * This is the default, and it is the only honest default. The alternative —
 * defaulting to a real provider — means installing the plugin without
 * configuring it blocks every protected route, and the first symptom is a
 * sign-up form that nobody can submit.
 *
 * It passes rather than fails for the same reason, but it is deliberately LOUD
 * about it: `describe()` says so in words a status command prints, and the
 * service logs a warning the first time a route relies on it. A captcha filter
 * that silently does nothing is worse than no filter, because the route looks
 * protected in `module.json` and in review.
 */
final class DisabledGateway implements CaptchaProvider
{
    public function name(): string
    {
        return 'disabled';
    }

    public function tokenField(): string
    {
        return 'captcha-response';
    }

    public function verify(string $token, ?string $remoteIp = null, ?string $expectedAction = null): CaptchaVerdict
    {
        return CaptchaVerdict::passed($this->name());
    }

    public function describe(): string
    {
        return 'disabled — NOTHING IS VERIFIED and every request passes the captcha filter';
    }
}
