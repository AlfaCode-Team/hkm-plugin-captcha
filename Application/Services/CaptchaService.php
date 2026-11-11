<?php

declare(strict_types=1);

namespace Plugins\Captcha\Application\Services;

use AlfacodeTeam\PhpServicePlatform\Kernel\Ports\LoggerPort;
use Plugins\Captcha\API\Contracts\CaptchaVerifierContract;
use Plugins\Captcha\Domain\CaptchaOutcome;
use Plugins\Captcha\Domain\CaptchaVerdict;
use Plugins\Captcha\Domain\Contracts\CaptchaProvider;
use Plugins\Captcha\Infrastructure\Config\CaptchaConfig;

final class CaptchaService implements CaptchaVerifierContract
{
    private bool $warnedAboutDisabled = false;

    public function __construct(
        private readonly CaptchaProvider $provider,
        private readonly CaptchaConfig $config,
        private readonly ?LoggerPort $logger = null,
    ) {}

    public function verify(string $token, ?string $remoteIp = null, ?string $expectedAction = null): CaptchaVerdict
    {
        if ($this->isDisabled()) {
            $this->warnOnceAboutDisabled();

            return $this->provider->verify($token, null, null);
        }

        $verdict = $this->provider->verify(
            $token,
            $this->config->sendIp ? $remoteIp : null,
            $expectedAction,
        );

        $this->log($verdict);

        return $verdict;
    }

    /**
     * WHETHER A VERDICT LETS THE REQUEST THROUGH — and the one real decision in
     * this plugin.
     *
     * A provider outage is not a failed challenge, so something has to choose
     * what happens. The kernel's WafLayer fails OPEN, with the reasoning that a
     * firewall whose cache outage takes the site down has become the attack.
     * This plugin defaults the OTHER WAY, and the difference is deliberate:
     *
     *   - the WAF inspects EVERY request, so failing closed takes the whole
     *     application down; a captcha guards a handful of named routes, so
     *     failing closed costs those routes and nothing else;
     *   - a route carries this filter because it is specifically under attack —
     *     sign-up, password reset, a public voting endpoint. Opening it during
     *     an outage removes the protection at the moment it is most likely to be
     *     probed, and an attacker who can cause the outage gets the bypass.
     *
     * So: Unavailable BLOCKS, unless CAPTCHA_FAIL_OPEN says otherwise. The flag
     * exists because the trade is real and an operator running a sign-up funnel
     * may legitimately prefer the bots.
     *
     * Misconfigured ALWAYS blocks, and is not covered by the flag. A wrong
     * secret is not an outage: it rejects every visitor, is entirely within the
     * operator's control, and opening the gate on it would mean a mistyped
     * secret silently disabled the protection for as long as nobody noticed.
     */
    public function allows(CaptchaVerdict $verdict): bool
    {
        if ($verdict->isPass()) {
            return true;
        }

        return $verdict->outcome === CaptchaOutcome::Unavailable && $this->config->failOpen;
    }

    public function tokenField(): string
    {
        return $this->provider->tokenField();
    }

    public function isDisabled(): bool
    {
        return $this->config->isDisabled();
    }

    public function describe(): string
    {
        $parts = [$this->provider->describe()];

        if (!$this->isDisabled()) {
            $parts[] = $this->config->failOpen
                ? 'FAIL OPEN on provider outage'
                : 'fail closed on provider outage';
            $parts[] = $this->config->sendIp ? 'sending remoteip' : 'not sending remoteip';
        }

        return implode('; ', $parts);
    }

    /** The message a denial shows, overridable so this plugin needs no i18n dependency. */
    public function denyMessage(CaptchaVerdict $verdict): string
    {
        if ($this->config->denyMessage !== null) {
            return $this->config->denyMessage;
        }

        return match ($verdict->outcome) {
            // Retryable outcomes must not accuse the visitor. A single-use token
            // resubmitted after a validation error is the commonest cause, and
            // "you appear to be a bot" is both wrong and unactionable.
            CaptchaOutcome::Replayed => 'That verification has already been used. Please complete the challenge again.',
            CaptchaOutcome::Missing  => 'Please complete the verification challenge and try again.',
            // Deliberately vague: naming the cause tells an attacker whether the
            // secret is wrong or the service is down.
            default                  => 'Verification failed. Please try again.',
        };
    }

    private function log(CaptchaVerdict $verdict): void
    {
        if ($this->logger === null) {
            return;
        }

        $context = ['verdict' => $verdict->describe()];

        // An operator fault is not traffic. A spike of Misconfigured is a deploy
        // that shipped the wrong key and needs to be seen; a spike of Failed is
        // the plugin doing its job and must not drown it out.
        if ($verdict->outcome->isOperatorFault()) {
            $this->logger->error('captcha.' . $verdict->outcome->value, $context);

            return;
        }

        if ($verdict->isPass()) {
            $this->logger->debug('captcha.passed', $context);

            return;
        }

        $this->logger->info('captcha.' . $verdict->outcome->value, $context);
    }

    /**
     * Say once per process that nothing is being verified.
     *
     * A captcha filter that silently passes everything is worse than no filter:
     * the route looks protected in module.json and in review. Once, not per
     * request, because a disabled captcha on a busy route would otherwise be the
     * loudest thing in the log.
     */
    private function warnOnceAboutDisabled(): void
    {
        if ($this->warnedAboutDisabled) {
            return;
        }

        $this->warnedAboutDisabled = true;

        $this->logger?->warning('captcha.disabled', [
            'detail' => 'A route declared the captcha filter but CAPTCHA_PROVIDER is disabled, '
                . 'so every request passes it.',
        ]);
    }
}
