<?php

declare(strict_types=1);

namespace Plugins\Captcha\Infrastructure\Gateways;

use AlfacodeTeam\PhpServicePlatform\Kernel\Ports\HttpClientPort;

/**
 * Google reCAPTCHA, v2 and v3 through one gateway.
 *
 *   POST https://www.google.com/recaptcha/api/siteverify
 *   secret, response, remoteip?
 *   → { success, challenge_ts, hostname, error-codes }  plus, on v3, { score, action }
 *
 * THE TRAP THIS CLASS EXISTS TO AVOID
 * -----------------------------------
 * On **v3 there is no pass or fail**. Google returns `success: true` for any
 * structurally valid, unspent token — including one a bot obtained — and puts
 * the actual judgement in `score`, from 0.0 (almost certainly a bot) to 1.0.
 * So a verifier that reads `success` alone accepts every bot on a v3 site while
 * appearing to work perfectly.
 *
 * On **v2 there is no score**, because the visitor solved a challenge and
 * `success` is the answer. A verifier that *requires* a score rejects every
 * human on a v2 site. Appwrite's own implementation does exactly that:
 * `packages/abuse/src/ReCaptcha.php` returns false unless a score is present
 * and above the threshold, which is correct for v3 and wrong for v2.
 *
 * Both mistakes are silent and opposite. The resolution here is to compare a
 * score only WHEN GOOGLE SENDS ONE — so v3 is scored, v2 is not, and neither
 * configuration can be broken by choosing the wrong class.
 */
final class RecaptchaGateway extends SiteVerifyGateway
{
    public function __construct(
        HttpClientPort $http,
        string $secret,
        /**
         * Google's own documented starting point is 0.5. It is a knob, not a
         * constant: the right value depends on the traffic, and the only way to
         * choose it is to run in monitoring and look at the distribution.
         */
        private readonly float $threshold = 0.5,
        int $timeout = 10,
    ) {
        parent::__construct($http, $secret, $timeout);
    }

    public function name(): string
    {
        return 'recaptcha';
    }

    public function tokenField(): string
    {
        return 'g-recaptcha-response';
    }

    protected function endpoint(): string
    {
        return 'https://www.google.com/recaptcha/api/siteverify';
    }

    /**
     * The threshold is always returned, and the base class applies it only when
     * a score actually came back. That is what makes one gateway correct for
     * both versions — see the class docblock.
     */
    protected function scoreThreshold(): ?float
    {
        return $this->threshold;
    }
}
