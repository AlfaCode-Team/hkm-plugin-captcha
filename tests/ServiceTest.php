<?php

declare(strict_types=1);

namespace Tests\Plugins\Captcha;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use Plugins\Captcha\Application\Services\CaptchaService;
use Plugins\Captcha\Domain\CaptchaOutcome;
use Plugins\Captcha\Domain\CaptchaVerdict;
use Plugins\Captcha\Infrastructure\CaptchaFactory;
use Plugins\Captcha\Infrastructure\Config\CaptchaConfig;
use Plugins\Captcha\Infrastructure\Exceptions\CaptchaException;
use Plugins\Captcha\Infrastructure\Gateways\DisabledGateway;
use Plugins\Captcha\Infrastructure\Gateways\TurnstileGateway;
use Tests\Plugins\Captcha\Support\FakeHttpClient;

#[CoversClass(CaptchaService::class)]
#[CoversClass(CaptchaFactory::class)]
#[CoversClass(CaptchaConfig::class)]
#[CoversClass(DisabledGateway::class)]
#[CoversClass(CaptchaOutcome::class)]
#[CoversClass(CaptchaVerdict::class)]
final class ServiceTest extends TestCase
{
    private function service(CaptchaConfig $config, ?FakeHttpClient $http = null): CaptchaService
    {
        return CaptchaFactory::make($config, $http ?? new FakeHttpClient());
    }

    // ── Fail open vs fail closed: the one real decision here ──────────────────

    public function test_an_outage_blocks_by_default(): void
    {
        $service = $this->service(CaptchaConfig::of(provider: 'turnstile', secret: 's'));

        $verdict = CaptchaVerdict::unavailable('turnstile', 'timed out');

        // The OPPOSITE of the kernel's WafLayer, deliberately: a route carries
        // this filter because it is specifically under attack, so opening it
        // during an outage removes the protection exactly when it is most likely
        // being probed — and an attacker who can cause the outage gets a bypass.
        self::assertFalse($service->allows($verdict));
    }

    public function test_fail_open_lets_an_outage_through(): void
    {
        $service = $this->service(CaptchaConfig::of(provider: 'turnstile', secret: 's', failOpen: true));

        self::assertTrue($service->allows(CaptchaVerdict::unavailable('turnstile', 'timed out')));
    }

    public function test_fail_open_does_not_excuse_a_wrong_secret(): void
    {
        $service = $this->service(CaptchaConfig::of(provider: 'turnstile', secret: 's', failOpen: true));

        // A wrong secret is not an outage: it is entirely within the operator's
        // control and rejects every visitor. Opening the gate on it would mean a
        // mistyped secret silently disabled the protection for as long as nobody
        // noticed.
        self::assertFalse($service->allows(
            CaptchaVerdict::misconfigured('turnstile', ['invalid-input-secret'], 'wrong secret'),
        ));
    }

    public function test_fail_open_never_excuses_a_real_failure(): void
    {
        $service = $this->service(CaptchaConfig::of(provider: 'turnstile', secret: 's', failOpen: true));

        self::assertFalse($service->allows(CaptchaVerdict::failed('turnstile', ['bad-request'])));
        self::assertFalse($service->allows(CaptchaVerdict::replayed('turnstile', ['timeout-or-duplicate'])));
        self::assertFalse($service->allows(CaptchaVerdict::missing('turnstile')));
    }

    public function test_only_a_pass_is_allowed_when_failing_closed(): void
    {
        $service = $this->service(CaptchaConfig::of(provider: 'turnstile', secret: 's'));

        self::assertTrue($service->allows(CaptchaVerdict::passed('turnstile')));
    }

    // ── Disabled ──────────────────────────────────────────────────────────────

    public function test_disabled_is_the_default_and_passes_everything(): void
    {
        $service = $this->service(CaptchaConfig::of());

        self::assertTrue($service->isDisabled());

        // Passes rather than blocks, because installing the plugin without
        // configuring it must not take every protected route down.
        $verdict = $service->verify('');
        self::assertTrue($verdict->isPass());
        self::assertSame('disabled', $verdict->provider);
    }

    public function test_disabled_says_so_in_words(): void
    {
        $described = $this->service(CaptchaConfig::of())->describe();

        // A captcha filter that silently passes everything is worse than no
        // filter: the route looks protected in module.json and in review.
        self::assertStringContainsString('NOTHING IS VERIFIED', $described);
    }

    public function test_disabled_makes_no_request(): void
    {
        $http = new FakeHttpClient(); // nothing scripted

        $this->service(CaptchaConfig::of(), $http)->verify('some-token');

        self::assertSame([], $http->requests);
    }

    // ── Configuration ─────────────────────────────────────────────────────────

    public function test_an_unknown_provider_is_refused_rather_than_disabled(): void
    {
        try {
            CaptchaFactory::provider(CaptchaConfig::of(provider: 'turnstyle', secret: 's'), new FakeHttpClient());
            self::fail('expected a refusal');
        } catch (CaptchaException $e) {
            // Falling back to disabled would leave every protected route passing
            // everything while the manifest and the diff still show a filter.
            self::assertStringContainsString('turnstyle', $e->getMessage());
            self::assertStringContainsString('turnstile, recaptcha, hcaptcha', $e->getMessage());
        }
    }

    public function test_a_missing_secret_names_the_right_key(): void
    {
        try {
            CaptchaFactory::provider(CaptchaConfig::of(provider: 'turnstile'), new FakeHttpClient());
            self::fail('expected a refusal');
        } catch (CaptchaException $e) {
            // People reach for the site key, which is the public one in the page.
            self::assertStringContainsString('CAPTCHA_SECRET', $e->getMessage());
            self::assertStringContainsString('not the public site key', $e->getMessage());
        }
    }

    public function test_verification_needs_an_http_client(): void
    {
        $this->expectException(CaptchaException::class);
        $this->expectExceptionMessageMatches('/http\.client/');

        CaptchaFactory::provider(CaptchaConfig::of(provider: 'turnstile', secret: 's'), null);
    }

    public function test_the_score_threshold_is_clamped(): void
    {
        // Outside 0.0–1.0 a threshold is silently useless in one direction or
        // the other: above 1.0 nothing passes, below 0.0 everything does.
        foreach ([['2.5', 1.0], ['-1', 0.0], ['0.3', 0.3], ['', 0.5]] as [$raw, $expected]) {
            $_ENV['CAPTCHA_SCORE_THRESHOLD'] = $raw;

            try {
                self::assertSame($expected, CaptchaConfig::fromEnv()->scoreThreshold, "[{$raw}]");
            } finally {
                unset($_ENV['CAPTCHA_SCORE_THRESHOLD']);
            }
        }
    }

    public function test_the_remote_ip_is_withheld_unless_asked_for(): void
    {
        $http = (new FakeHttpClient())
            ->willReturnJson(200, ['success' => true])
            ->willReturnJson(200, ['success' => true]);

        // Behind a CDN the address this process sees is the proxy's, and every
        // vendor treats a remoteip that disagrees with the token's origin as a
        // reason to fail — hCaptcha has a dedicated invalid-remoteip code.
        $this->service(CaptchaConfig::of(provider: 'turnstile', secret: 's'), $http)
            ->verify('t', '203.0.113.9');
        self::assertArrayNotHasKey('remoteip', $http->lastForm());

        $this->service(CaptchaConfig::of(provider: 'turnstile', secret: 's', sendIp: true), $http)
            ->verify('t', '203.0.113.9');
        self::assertSame('203.0.113.9', $http->lastForm()['remoteip'] ?? null);
    }

    public function test_off_is_accepted_as_a_synonym_for_disabled(): void
    {
        self::assertTrue(CaptchaConfig::of(provider: 'off')->isDisabled());
        self::assertTrue(CaptchaConfig::of(provider: '')->isDisabled());
    }

    // ── Messages ──────────────────────────────────────────────────────────────

    public function test_a_retryable_outcome_does_not_accuse_the_visitor(): void
    {
        $service = $this->service(CaptchaConfig::of(provider: 'turnstile', secret: 's'));

        $replayed = $service->denyMessage(CaptchaVerdict::replayed('turnstile', ['timeout-or-duplicate']));
        $missing  = $service->denyMessage(CaptchaVerdict::missing('turnstile'));

        // The commonest cause of a replay on a real form is a person
        // resubmitting after a validation error with the same single-use token
        // still in the field. Telling them they look like a bot is wrong and
        // unactionable.
        self::assertStringContainsString('already been used', $replayed);
        self::assertStringContainsString('again', $missing);
        foreach ([$replayed, $missing] as $message) {
            self::assertStringNotContainsStringIgnoringCase('bot', $message);
        }
    }

    public function test_a_hard_failure_message_does_not_name_the_cause(): void
    {
        $service = $this->service(CaptchaConfig::of(provider: 'turnstile', secret: 's'));

        $message = $service->denyMessage(
            CaptchaVerdict::misconfigured('turnstile', ['invalid-input-secret'], 'wrong secret'),
        );

        // Naming it would tell an attacker whether the secret is wrong or the
        // service is down.
        self::assertStringNotContainsStringIgnoringCase('secret', $message);
        self::assertStringNotContainsStringIgnoringCase('outage', $message);
    }

    public function test_the_deny_message_is_overridable(): void
    {
        $service = $this->service(
            CaptchaConfig::of(provider: 'turnstile', secret: 's', denyMessage: 'Nope.'),
        );

        self::assertSame('Nope.', $service->denyMessage(CaptchaVerdict::failed('turnstile')));
        // Overriding covers every outcome, which is what lets a project
        // translate it without this plugin depending on i18n.
        self::assertSame('Nope.', $service->denyMessage(CaptchaVerdict::missing('turnstile')));
    }

    // ── Outcome semantics ─────────────────────────────────────────────────────

    public function test_outcome_predicates(): void
    {
        self::assertTrue(CaptchaOutcome::Passed->isPass());

        foreach ([CaptchaOutcome::Replayed, CaptchaOutcome::Missing] as $retryable) {
            self::assertTrue($retryable->isRetryable(), $retryable->value);
            self::assertFalse($retryable->isOperatorFault(), $retryable->value);
        }

        foreach ([CaptchaOutcome::Misconfigured, CaptchaOutcome::Unavailable] as $theirs) {
            self::assertTrue($theirs->isOperatorFault(), $theirs->value);
            self::assertFalse($theirs->isRetryable(), $theirs->value);
        }

        // Failed is the ONLY outcome that means "bot".
        self::assertFalse(CaptchaOutcome::Failed->isRetryable());
        self::assertFalse(CaptchaOutcome::Failed->isOperatorFault());
    }

    public function test_the_token_field_comes_from_the_provider(): void
    {
        $service = $this->service(CaptchaConfig::of(provider: 'turnstile', secret: 's'));

        self::assertSame('cf-turnstile-response', $service->tokenField());
        self::assertSame(
            'g-recaptcha-response',
            $this->service(CaptchaConfig::of(provider: 'recaptcha', secret: 's'))->tokenField(),
        );
    }

    public function test_a_turnstile_gateway_is_built_for_the_turnstile_provider(): void
    {
        self::assertInstanceOf(
            TurnstileGateway::class,
            CaptchaFactory::provider(CaptchaConfig::of(provider: 'turnstile', secret: 's'), new FakeHttpClient()),
        );
    }
}
