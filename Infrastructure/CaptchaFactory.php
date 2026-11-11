<?php

declare(strict_types=1);

namespace Plugins\Captcha\Infrastructure;

use AlfacodeTeam\PhpServicePlatform\Kernel\Ports\HttpClientPort;
use AlfacodeTeam\PhpServicePlatform\Kernel\Ports\LoggerPort;
use Plugins\Captcha\Application\Services\CaptchaService;
use Plugins\Captcha\Domain\Contracts\CaptchaProvider;
use Plugins\Captcha\Infrastructure\Config\CaptchaConfig;
use Plugins\Captcha\Infrastructure\Exceptions\CaptchaException;
use Plugins\Captcha\Infrastructure\Gateways\DisabledGateway;
use Plugins\Captcha\Infrastructure\Gateways\HcaptchaGateway;
use Plugins\Captcha\Infrastructure\Gateways\RecaptchaGateway;
use Plugins\Captcha\Infrastructure\Gateways\TurnstileGateway;

final class CaptchaFactory
{
    public static function make(
        CaptchaConfig $config,
        ?HttpClientPort $http = null,
        ?LoggerPort $logger = null,
    ): CaptchaService {
        return new CaptchaService(
            provider: self::provider($config, $http),
            config:   $config,
            logger:   $logger,
        );
    }

    public static function provider(CaptchaConfig $config, ?HttpClientPort $http = null): CaptchaProvider
    {
        if ($config->isDisabled()) {
            return new DisabledGateway();
        }

        if (!\in_array($config->provider, self::available(), true)) {
            // Refused, never silently disabled. A typo in CAPTCHA_PROVIDER
            // falling back to the disabled gateway would leave every protected
            // route passing everything, while module.json and code review both
            // still show a captcha filter on it.
            throw CaptchaException::notConfigured(sprintf(
                'CAPTCHA_PROVIDER is [%s], which is not a provider this plugin has. Use one of: %s, or disabled.',
                $config->provider,
                implode(', ', self::available()),
            ));
        }

        if ($http === null) {
            throw CaptchaException::notConfigured(
                'verification needs the http.client domain; add the HttpClient plugin, '
                . 'or this module\'s requires[] is not being honoured.'
            );
        }

        if ($config->secret === null) {
            throw CaptchaException::notConfigured(
                "the [{$config->provider}] provider needs CAPTCHA_SECRET — the SERVER-side secret, "
                . 'not the public site key that goes in the page.'
            );
        }

        return match ($config->provider) {
            'turnstile' => new TurnstileGateway($http, $config->secret, $config->timeout),
            'recaptcha' => new RecaptchaGateway($http, $config->secret, $config->scoreThreshold, $config->timeout),
            'hcaptcha'  => new HcaptchaGateway(
                $http,
                $config->secret,
                $config->siteKey,
                // Null unless an operator asked for one: the hCaptcha score is
                // Enterprise-only, and a threshold on a plan that sends no score
                // would read it as 0 and reject everyone.
                null,
                $config->timeout,
            ),
            default     => throw CaptchaException::notConfigured("unreachable provider [{$config->provider}]"),
        };
    }

    /** @return list<string> */
    public static function available(): array
    {
        return ['turnstile', 'recaptcha', 'hcaptcha'];
    }
}
