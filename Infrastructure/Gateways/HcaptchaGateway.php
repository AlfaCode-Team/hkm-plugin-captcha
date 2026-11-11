<?php

declare(strict_types=1);

namespace Plugins\Captcha\Infrastructure\Gateways;

use AlfacodeTeam\PhpServicePlatform\Kernel\Ports\HttpClientPort;

/**
 * hCaptcha.
 *
 *   POST https://api.hcaptcha.com/siteverify
 *   secret, response, remoteip?, sitekey?
 *   → { success, challenge_ts, hostname, error-codes }  plus, on Enterprise, { score }
 *
 * Two things are specific to this vendor:
 *
 *  - **`sitekey` is worth sending.** hCaptcha documents it as preventing a token
 *    issued for one sitekey being redeemed against another. Without it, a token
 *    harvested from any other site using the same secret-holder's account is
 *    accepted here.
 *  - **The score is Enterprise-only**, so the threshold stays null by default. A
 *    threshold on a non-Enterprise account would read a missing score as 0 and
 *    reject everyone.
 */
final class HcaptchaGateway extends SiteVerifyGateway
{
    public function __construct(
        HttpClientPort $http,
        string $secret,
        private readonly ?string $siteKey = null,
        private readonly ?float $threshold = null,
        int $timeout = 10,
    ) {
        parent::__construct($http, $secret, $timeout);
    }

    public function name(): string
    {
        return 'hcaptcha';
    }

    public function tokenField(): string
    {
        return 'h-captcha-response';
    }

    protected function endpoint(): string
    {
        return 'https://api.hcaptcha.com/siteverify';
    }

    protected function scoreThreshold(): ?float
    {
        return $this->threshold;
    }

    /** @return array<string, string> */
    protected function extraFields(): array
    {
        return $this->siteKey === null || $this->siteKey === ''
            ? []
            : ['sitekey' => $this->siteKey];
    }

    public function describe(): string
    {
        return parent::describe()
            . ($this->siteKey === null ? ', sitekey NOT pinned (a token from another sitekey would be accepted)' : ', sitekey pinned');
    }
}
