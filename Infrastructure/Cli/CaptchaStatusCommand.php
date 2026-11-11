<?php

declare(strict_types=1);

namespace Plugins\Captcha\Infrastructure\Cli;

use AlfacodeTeam\PhpIoCli\AbstractCommand;
use Plugins\Captcha\Infrastructure\CaptchaFactory;
use Plugins\Captcha\Infrastructure\Config\CaptchaConfig;
use Plugins\Captcha\Infrastructure\Exceptions\CaptchaException;

/**
 * `captcha:status` — say what is configured, and whether anything is verified.
 *
 * The question it exists to answer is the one a filter cannot: a route can
 * declare `captcha` and have the provider disabled, in which case the route
 * looks protected everywhere a human would look — the manifest, the diff, the
 * review — and verifies nothing. This prints that in words.
 *
 * It does not send a verification. A valid token can only come from a real
 * widget in a real browser, so there is nothing a command could verify without
 * one; `captcha:status` reports configuration, and the honest proof is a request
 * through the form.
 */
final class CaptchaStatusCommand extends AbstractCommand
{
    protected function configure(): void
    {
        $this->name        = 'captcha:status';
        $this->description = 'Show the captcha configuration and whether requests are actually verified';
    }

    protected function handle(): int
    {
        $this->section('Captcha');

        $config = CaptchaConfig::fromEnv();

        $this->info('Provider: ' . $config->provider
            . ' (available: ' . implode(', ', CaptchaFactory::available()) . ', disabled)');

        if ($config->isDisabled()) {
            $this->warning(
                'NOTHING IS VERIFIED. Every request passes the captcha filter, including on '
                . 'routes that declare it — which look protected in module.json and in review.'
            );

            return self::SUCCESS;
        }

        try {
            // Built without an HttpClientPort on purpose: this checks the
            // configuration, and the factory's credential and provider-name
            // checks run before it needs one.
            $provider = CaptchaFactory::provider($config, null);
            $this->success($provider->describe());
        } catch (CaptchaException $e) {
            $this->error($e->getMessage());

            // A bare CLI container legitimately has no HttpClientPort, so that
            // particular failure is not a configuration fault and must not be
            // reported as one.
            if (str_contains($e->getMessage(), 'http.client')) {
                $this->muted('(the http.client domain is absent from this CLI container, which is normal)');
                $this->info('Secret: ' . ($config->secret === null ? 'MISSING' : 'set'));

                return $config->secret === null ? self::FAILURE : self::SUCCESS;
            }

            return self::FAILURE;
        }

        $this->info($config->failOpen
            ? 'On a provider outage: FAIL OPEN — requests are let through unverified'
            : 'On a provider outage: fail closed — requests are refused');

        $this->info($config->sendIp
            ? 'Sending remoteip — make sure the address this process sees is the VISITOR\'s, not a proxy\'s'
            : 'Not sending remoteip');

        $this->newLine();
        $this->muted('No verification was attempted: a valid token can only come from a real widget');
        $this->muted('in a browser, so only a request through the form proves this works.');

        return self::SUCCESS;
    }
}
