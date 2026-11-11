<?php

declare(strict_types=1);

namespace Plugins\Captcha\Domain\Contracts;

use Plugins\Captcha\Domain\CaptchaVerdict;

/**
 * One captcha service's server-side verification.
 *
 * Implementations live in Infrastructure/Gateways and may only talk to their
 * vendor. A provider NEVER throws for a failed challenge — a failure is a
 * verdict, not an exception — and never throws for an unreachable vendor
 * either, because whether that blocks the request is the operator's decision
 * and the verdict has an outcome for it.
 */
interface CaptchaProvider
{
    /** Short, stable, lower-case: 'turnstile', 'recaptcha', 'hcaptcha', 'disabled'. */
    public function name(): string;

    /**
     * The form field the widget writes its token into.
     *
     * Each vendor uses its own name, and the stage looks there first so a page
     * using the vendor's standard markup needs no extra wiring.
     */
    public function tokenField(): string;

    /**
     * @param string|null $remoteIp      the visitor's address, or null not to send one
     * @param string|null $expectedAction refuse a token minted for a different
     *                                    action, where the provider echoes it
     */
    public function verify(string $token, ?string $remoteIp = null, ?string $expectedAction = null): CaptchaVerdict;

    /** One line for a status command. MUST NOT contain the secret. */
    public function describe(): string;
}
