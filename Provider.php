<?php

declare(strict_types=1);

namespace Plugins\Captcha;

use AlfacodeTeam\PhpServicePlatform\Kernel\Container\ModuleContainer;
use AlfacodeTeam\PhpServicePlatform\Kernel\Contracts\ModuleContract;
use AlfacodeTeam\PhpServicePlatform\Kernel\Events\EventBus;
use AlfacodeTeam\PhpServicePlatform\Kernel\Pipelines\Cli\CliPipeline;
use AlfacodeTeam\PhpServicePlatform\Kernel\Pipelines\Http\HttpPipeline;
use AlfacodeTeam\PhpServicePlatform\Kernel\Pipelines\Worker\WorkerPipeline;
use AlfacodeTeam\PhpServicePlatform\Kernel\Ports\HttpClientPort;
use AlfacodeTeam\PhpServicePlatform\Kernel\Ports\LoggerPort;
use Plugins\Captcha\API\Contracts\CaptchaVerifierContract;
use Plugins\Captcha\Application\Services\CaptchaService;
use Plugins\Captcha\Infrastructure\CaptchaFactory;
use Plugins\Captcha\Infrastructure\Config\CaptchaConfig;
use Plugins\Captcha\Infrastructure\Http\Stages\VerifyCaptchaStage;

/**
 * Captcha — wires the 'captcha.verification' domain.
 *
 * Publishes the `captcha` route filter. Turnstile, reCAPTCHA (v2 and v3) and
 * hCaptcha behind one contract, verified server-side through HttpClientPort.
 */
final class Provider implements ModuleContract
{
    public function solves(): string
    {
        return 'captcha.verification';
    }

    /** @return list<string> module DOMAINS — mirrors module.json "requires" */
    public function requires(): array
    {
        return ['http.client'];
    }

    /** @return list<class-string> */
    public function exposes(): array
    {
        return [CaptchaVerifierContract::class];
    }

    public function register(ModuleContainer $container): void
    {
        $container->bindInternal(CaptchaConfig::class, static fn (): CaptchaConfig => CaptchaConfig::fromEnv());

        // Built inside the closure: register() runs in dependency-graph order,
        // so a port this module needs may not be bound yet at register() time.
        //
        // The factory THROWS on a misconfiguration, and that is deliberate —
        // but it throws on resolution rather than at boot, so a bad captcha
        // secret fails the protected route and leaves the rest of the
        // application serving.
        $container->bind(
            CaptchaVerifierContract::class,
            static fn (ModuleContainer $c): CaptchaService => CaptchaFactory::make(
                config: $c->make(CaptchaConfig::class),
                http:   $c->has(HttpClientPort::class) ? $c->make(HttpClientPort::class) : null,
                logger: $c->has(LoggerPort::class) ? $c->make(LoggerPort::class) : null,
            ),
        );
    }

    public function boot(HttpPipeline $http, CliPipeline $cli, WorkerPipeline $worker, EventBus $events): void
    {
        // A FILTER, never also a global hook. Registering both would run it
        // twice per request, and a captcha token is single-use: the second
        // verification returns `timeout-or-duplicate` and every protected
        // request would fail.
        $http->filter('captcha', VerifyCaptchaStage::class);
    }
}
