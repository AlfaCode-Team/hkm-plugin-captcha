<?php

declare(strict_types=1);

namespace Plugins\Captcha\Domain;

/**
 * What a verification actually concluded.
 *
 * A bool is not enough here, and the reason is the whole design of this plugin:
 * four of these six outcomes are NOT "this is a bot", and answering them all
 * with the same 403 either blocks real people or lets bots through.
 */
enum CaptchaOutcome: string
{
    /** The provider says this is a human (and, where scored, above the threshold). */
    case Passed = 'passed';

    /** The provider says no. The only outcome that means "bot". */
    case Failed = 'failed';

    /**
     * The token was already spent, or it expired.
     *
     * EVERY provider here issues SINGLE-USE tokens, and this is the outcome
     * people get wrong. It is reported identically for an attacker replaying a
     * captured token and for a real person whose form failed validation and who
     * pressed submit again with the same token still in the field. Telling that
     * person they look like a bot is wrong and unactionable; the correct
     * response is "solve it again", because the widget must mint a new token.
     *
     * Cloudflare names it `timeout-or-duplicate`, and the name is honest about
     * being two things at once.
     */
    case Replayed = 'replayed';

    /** No token arrived at all. Usually a front-end wiring mistake, not an attack. */
    case Missing = 'missing';

    /**
     * The provider could not be reached, or answered unintelligibly.
     *
     * Deliberately distinct from Failed. Whether this blocks the request is a
     * configuration decision (CAPTCHA_FAIL_OPEN) and not something a verifier
     * should decide on an operator's behalf.
     */
    case Unavailable = 'unavailable';

    /**
     * The SECRET is wrong, missing, or the token belongs to another site key.
     *
     * This is an operator error reported by the provider, and it must never be
     * presented as a failed challenge: a wrong secret rejects every human on the
     * site, and a 403 saying "captcha failed" sends everyone looking in the
     * wrong place.
     */
    case Misconfigured = 'misconfigured';

    /** True only for Passed. */
    public function isPass(): bool
    {
        return $this === self::Passed;
    }

    /** Should the visitor be asked to try again rather than told they failed? */
    public function isRetryable(): bool
    {
        return $this === self::Replayed || $this === self::Missing;
    }

    /**
     * Is this the operator's problem rather than the visitor's?
     *
     * Worth logging at a higher level, and worth distinguishing in metrics: a
     * spike of Misconfigured is a deploy that shipped the wrong key, while a
     * spike of Failed is traffic.
     */
    public function isOperatorFault(): bool
    {
        return $this === self::Misconfigured || $this === self::Unavailable;
    }
}
