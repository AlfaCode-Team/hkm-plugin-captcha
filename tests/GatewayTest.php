<?php

declare(strict_types=1);

namespace Tests\Plugins\Captcha;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use Plugins\Captcha\Domain\CaptchaOutcome;
use Plugins\Captcha\Infrastructure\Gateways\HcaptchaGateway;
use Plugins\Captcha\Infrastructure\Gateways\RecaptchaGateway;
use Plugins\Captcha\Infrastructure\Gateways\SiteVerifyGateway;
use Plugins\Captcha\Infrastructure\Gateways\TurnstileGateway;
use Tests\Plugins\Captcha\Support\FakeHttpClient;

/**
 * The request each vendor gets, and how each answer is classified.
 *
 * No request has ever reached a vendor from this suite — see the README. What
 * is asserted here is the half this plugin owns: the endpoint, the field names,
 * and the classification of every documented error code. Getting a code into
 * the wrong bucket is silent and expensive in both directions — a wrong secret
 * reported as a failed challenge sends the whole team looking at the widget,
 * and a spent token reported as a failure tells a real person they are a bot.
 */
#[CoversClass(SiteVerifyGateway::class)]
#[CoversClass(TurnstileGateway::class)]
#[CoversClass(RecaptchaGateway::class)]
#[CoversClass(HcaptchaGateway::class)]
final class GatewayTest extends TestCase
{
    private const SECRET = '0xTHE-SERVER-SIDE-SECRET';

    // ── The request ───────────────────────────────────────────────────────────

    /** @return list<array{string, string, string}> */
    public static function endpoints(): array
    {
        return [
            ['turnstile', 'https://challenges.cloudflare.com/turnstile/v0/siteverify', 'cf-turnstile-response'],
            ['recaptcha', 'https://www.google.com/recaptcha/api/siteverify', 'g-recaptcha-response'],
            ['hcaptcha', 'https://api.hcaptcha.com/siteverify', 'h-captcha-response'],
        ];
    }

    #[DataProvider('endpoints')]
    public function test_each_vendor_gets_its_own_endpoint_and_field_name(string $name, string $url, string $field): void
    {
        $http    = (new FakeHttpClient())->willReturnJson(200, ['success' => true]);
        $gateway = $this->gateway($name, $http);

        $gateway->verify('a-token');

        self::assertSame($name, $gateway->name());
        self::assertSame($field, $gateway->tokenField());
        self::assertSame('POST', $http->lastRequest()['method']);
        self::assertSame($url, $http->lastRequest()['url']);
    }

    public function test_the_form_body_is_secret_and_response(): void
    {
        $http = (new FakeHttpClient())->willReturnJson(200, ['success' => true]);

        $this->gateway('turnstile', $http)->verify('a-token');

        // All three vendors name these two fields identically. A body keyed
        // 'token' or 'secret_key' is accepted as a malformed request and comes
        // back as a failure, which reads as a broken captcha.
        self::assertSame(['secret' => self::SECRET, 'response' => 'a-token'], $http->lastForm());
    }

    public function test_the_remote_ip_is_only_sent_when_given(): void
    {
        $http = (new FakeHttpClient())
            ->willReturnJson(200, ['success' => true])
            ->willReturnJson(200, ['success' => true]);

        $gateway = $this->gateway('turnstile', $http);

        $gateway->verify('t');
        self::assertArrayNotHasKey('remoteip', $http->lastForm());

        $gateway->verify('t', '203.0.113.9');
        self::assertSame('203.0.113.9', $http->lastForm()['remoteip'] ?? null);
    }

    public function test_hcaptcha_pins_the_sitekey_when_configured(): void
    {
        $http = (new FakeHttpClient())->willReturnJson(200, ['success' => true]);

        (new HcaptchaGateway($http, self::SECRET, siteKey: 'SITE-123'))->verify('t');

        // hCaptcha documents sitekey as preventing a token issued for one
        // sitekey being redeemed against another.
        self::assertSame('SITE-123', $http->lastForm()['sitekey'] ?? null);
    }

    public function test_it_never_retries(): void
    {
        $http = (new FakeHttpClient())->willReturnJson(200, ['success' => true]);

        $this->gateway('turnstile', $http)->verify('t');

        // A token is single-use at every vendor here, so a retry of a request
        // the vendor already processed returns timeout-or-duplicate — turning a
        // network blip into what looks like a replay attack on a real visitor.
        self::assertSame(0, $http->lastRequest()['options']['retry'] ?? null);
    }

    public function test_an_empty_token_is_not_sent_at_all(): void
    {
        $http = new FakeHttpClient(); // nothing scripted: nothing may be sent

        $verdict = $this->gateway('turnstile', $http)->verify('   ');

        self::assertSame(CaptchaOutcome::Missing, $verdict->outcome);
        self::assertSame([], $http->requests);
    }

    // ── The classification ────────────────────────────────────────────────────

    /** @return list<array{list<string>, CaptchaOutcome}> */
    public static function errorCodes(): array
    {
        return [
            // Operator fault. Rejects every visitor, and must never be reported
            // as a failed challenge.
            [['missing-input-secret'], CaptchaOutcome::Misconfigured],
            [['invalid-input-secret'], CaptchaOutcome::Misconfigured],
            [['sitekey-secret-mismatch'], CaptchaOutcome::Misconfigured],
            [['not-using-dummy-passcode'], CaptchaOutcome::Misconfigured],

            // Spent or expired: the visitor needs a NEW token, and is not a bot.
            [['timeout-or-duplicate'], CaptchaOutcome::Replayed],
            [['expired-input-response'], CaptchaOutcome::Replayed],
            [['already-seen-response'], CaptchaOutcome::Replayed],

            // The field never arrived.
            [['missing-input-response'], CaptchaOutcome::Missing],

            // A malformed token IS a failure, not something to retry. Getting
            // this one wrong was a bug in the first draft of this plugin.
            [['invalid-input-response'], CaptchaOutcome::Failed],
            [['bad-request'], CaptchaOutcome::Failed],
            [['internal-error'], CaptchaOutcome::Failed],
            [[], CaptchaOutcome::Failed],
        ];
    }

    /** @param list<string> $codes */
    #[DataProvider('errorCodes')]
    public function test_error_codes_are_classified(array $codes, CaptchaOutcome $expected): void
    {
        $http = (new FakeHttpClient())->willReturnJson(200, ['success' => false, 'error-codes' => $codes]);

        $verdict = $this->gateway('turnstile', $http)->verify('t');

        self::assertSame($expected, $verdict->outcome, implode(',', $codes));
        self::assertSame($codes, $verdict->errorCodes);
    }

    public function test_a_secret_problem_wins_over_a_replay_code(): void
    {
        // Order matters: with both present, the operator fault is the one that
        // needs reporting, because it is the one that breaks the site.
        $http = (new FakeHttpClient())->willReturnJson(200, [
            'success'     => false,
            'error-codes' => ['timeout-or-duplicate', 'invalid-input-secret'],
        ]);

        self::assertSame(
            CaptchaOutcome::Misconfigured,
            $this->gateway('turnstile', $http)->verify('t')->outcome,
        );
    }

    public function test_an_unreachable_vendor_is_unavailable_not_failed(): void
    {
        $http = (new FakeHttpClient())->willThrow(new \RuntimeException('connection refused'));

        $verdict = $this->gateway('turnstile', $http)->verify('t');

        // Distinct from Failed so the fail-open decision stays the operator's.
        self::assertSame(CaptchaOutcome::Unavailable, $verdict->outcome);
        self::assertStringContainsString('connection refused', (string) $verdict->detail);
    }

    public function test_a_non_json_body_is_unavailable(): void
    {
        $http = (new FakeHttpClient())->willReturn(502, '<html>Bad Gateway</html>');

        $verdict = $this->gateway('turnstile', $http)->verify('t');

        self::assertSame(CaptchaOutcome::Unavailable, $verdict->outcome);
        self::assertStringContainsString('502', (string) $verdict->detail);
    }

    // ── Scores: the trap ──────────────────────────────────────────────────────

    public function test_recaptcha_v3_enforces_the_score_even_when_success_is_true(): void
    {
        // THE central reCAPTCHA v3 trap. Google returns success:true for any
        // structurally valid unspent token, including one a bot obtained, and
        // puts the judgement in `score`. A verifier reading success alone
        // accepts every bot while appearing to work perfectly.
        $http = (new FakeHttpClient())->willReturnJson(200, ['success' => true, 'score' => 0.1]);

        $verdict = (new RecaptchaGateway($http, self::SECRET, threshold: 0.5))->verify('t');

        self::assertSame(CaptchaOutcome::Failed, $verdict->outcome);
        self::assertSame(0.1, $verdict->score);
        self::assertStringContainsString('below the threshold', (string) $verdict->detail);
    }

    public function test_recaptcha_v3_passes_at_or_above_the_threshold(): void
    {
        foreach ([0.5, 0.9] as $score) {
            $http    = (new FakeHttpClient())->willReturnJson(200, ['success' => true, 'score' => $score]);
            $verdict = (new RecaptchaGateway($http, self::SECRET, threshold: 0.5))->verify('t');

            self::assertTrue($verdict->isPass(), "score {$score}");
            self::assertSame($score, $verdict->score);
        }
    }

    public function test_recaptcha_v2_passes_with_no_score_at_all(): void
    {
        // The OPPOSITE trap, and the one Appwrite's own verifier falls into
        // (packages/abuse/src/ReCaptcha.php returns false unless a score is
        // present and above the threshold). On v2 the visitor solved a
        // challenge and there IS no score — requiring one rejects every human
        // on the site.
        $http = (new FakeHttpClient())->willReturnJson(200, ['success' => true]);

        $verdict = (new RecaptchaGateway($http, self::SECRET, threshold: 0.5))->verify('t');

        self::assertTrue($verdict->isPass());
        self::assertNull($verdict->score, 'a missing score must stay null, never become 0.0');
    }

    public function test_turnstile_has_no_threshold_so_success_is_the_whole_answer(): void
    {
        // Turnstile sends no score on any non-Enterprise plan. A threshold here
        // would read the absence as 0 and reject everyone.
        $http = (new FakeHttpClient())->willReturnJson(200, ['success' => true]);

        self::assertTrue($this->gateway('turnstile', $http)->verify('t')->isPass());
    }

    public function test_hcaptcha_does_not_score_by_default(): void
    {
        // The hCaptcha score is Enterprise-only.
        $http = (new FakeHttpClient())->willReturnJson(200, ['success' => true]);

        self::assertTrue((new HcaptchaGateway($http, self::SECRET))->verify('t')->isPass());
    }

    // ── Action binding ────────────────────────────────────────────────────────

    public function test_a_token_minted_for_another_action_is_refused(): void
    {
        // Without this, a token harvested from a public newsletter widget
        // satisfies the captcha on /password/reset.
        $http = (new FakeHttpClient())->willReturnJson(200, ['success' => true, 'action' => 'newsletter']);

        $verdict = $this->gateway('turnstile', $http)->verify('t', null, 'password-reset');

        self::assertSame(CaptchaOutcome::Failed, $verdict->outcome);
        self::assertStringContainsString('newsletter', (string) $verdict->detail);
        self::assertStringContainsString('password-reset', (string) $verdict->detail);
    }

    public function test_a_matching_action_passes_and_is_reported(): void
    {
        $http = (new FakeHttpClient())->willReturnJson(200, ['success' => true, 'action' => 'register']);

        $verdict = $this->gateway('turnstile', $http)->verify('t', null, 'register');

        self::assertTrue($verdict->isPass());
        self::assertSame('register', $verdict->action);
    }

    public function test_no_action_echoed_back_cannot_fail_the_check(): void
    {
        // reCAPTCHA v2, and a Turnstile widget with no action configured, send
        // none. Treating that as a mismatch would reject every visitor.
        $http = (new FakeHttpClient())->willReturnJson(200, ['success' => true]);

        self::assertTrue($this->gateway('turnstile', $http)->verify('t', null, 'register')->isPass());
    }

    // ── Secrets ───────────────────────────────────────────────────────────────

    public function test_describe_never_reveals_the_secret(): void
    {
        foreach (['turnstile', 'recaptcha', 'hcaptcha'] as $name) {
            $described = $this->gateway($name, new FakeHttpClient())->describe();

            self::assertStringNotContainsString(self::SECRET, $described, $name);
            self::assertStringContainsString('secret set', $described, $name);
        }
    }

    public function test_the_verdict_description_carries_no_token(): void
    {
        $http = (new FakeHttpClient())->willReturnJson(200, ['success' => false, 'error-codes' => ['bad-request']]);

        $described = $this->gateway('turnstile', $http)->verify('a-secret-bearer-token')->describe();

        // The token is a bearer credential for one verification; the error codes
        // are enough to diagnose without it.
        self::assertStringNotContainsString('a-secret-bearer-token', $described);
    }

    private function gateway(string $name, FakeHttpClient $http): SiteVerifyGateway
    {
        return match ($name) {
            'turnstile' => new TurnstileGateway($http, self::SECRET),
            'recaptcha' => new RecaptchaGateway($http, self::SECRET),
            'hcaptcha'  => new HcaptchaGateway($http, self::SECRET),
            default     => throw new \LogicException("no gateway [{$name}]"),
        };
    }
}
