<?php

declare(strict_types=1);

namespace Plugins\Captcha\Infrastructure\Gateways;

/**
 * Cloudflare Turnstile.
 *
 * Endpoint and fields from Cloudflare's server-side validation reference:
 *
 *   POST https://challenges.cloudflare.com/turnstile/v0/siteverify
 *   secret, response, remoteip?, idempotency_key?
 *   → { success, challenge_ts, hostname, error-codes, action, cdata }
 *
 * **Turnstile does not score.** The response carries no `score` field at all on
 * any non-Enterprise plan, so the threshold is null and the `success` boolean is
 * the whole answer. Applying a threshold here would read a missing score as 0
 * and reject every visitor.
 */
final class TurnstileGateway extends SiteVerifyGateway
{
    public function name(): string
    {
        return 'turnstile';
    }

    public function tokenField(): string
    {
        return 'cf-turnstile-response';
    }

    protected function endpoint(): string
    {
        return 'https://challenges.cloudflare.com/turnstile/v0/siteverify';
    }

    protected function scoreThreshold(): ?float
    {
        return null;
    }
}
