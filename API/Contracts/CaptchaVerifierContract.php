<?php

declare(strict_types=1);

namespace Plugins\Captcha\API\Contracts;

use Plugins\Captcha\Domain\CaptchaVerdict;

/**
 * The published surface of `captcha.verification`.
 *
 * Most routes should not use this: declaring the `captcha` filter in
 * `module.json` is the intended path and needs no code. This is for the cases a
 * filter cannot express — a captcha required only for a particular branch of a
 * service, or a verdict that has to be recorded rather than enforced.
 */
interface CaptchaVerifierContract
{
    /**
     * @param string|null $remoteIp       the visitor's address, or null to send none
     * @param string|null $expectedAction refuse a token minted for another action
     *
     * Never throws for a failed challenge — that is a verdict. Throws only when
     * the plugin cannot verify at all.
     *
     * @throws \Plugins\Captcha\Infrastructure\Exceptions\CaptchaException
     */
    public function verify(string $token, ?string $remoteIp = null, ?string $expectedAction = null): CaptchaVerdict;

    /**
     * Should a request carrying this verdict be allowed through?
     *
     * Separate from the verdict because the answer depends on configuration, not
     * on the verdict alone: an Unavailable outcome passes when CAPTCHA_FAIL_OPEN
     * is set and blocks when it is not.
     */
    public function allows(CaptchaVerdict $verdict): bool;

    /** The form field this provider's widget writes its token into. */
    public function tokenField(): string;

    /** True when nothing is being verified. */
    public function isDisabled(): bool;

    /** One line for a status command. Never contains the secret. */
    public function describe(): string;
}
