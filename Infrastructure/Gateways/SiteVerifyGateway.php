<?php

declare(strict_types=1);

namespace Plugins\Captcha\Infrastructure\Gateways;

use AlfacodeTeam\PhpServicePlatform\Kernel\Ports\HttpClientPort;
use Plugins\Captcha\Domain\Contracts\CaptchaProvider;
use Plugins\Captcha\Domain\CaptchaVerdict;

/**
 * The siteverify protocol the three vendors share.
 *
 * Cloudflare Turnstile, Google reCAPTCHA and hCaptcha all expose the same shape:
 * POST a form body of `secret` + `response` (+ optional `remoteip`) and get back
 * JSON with a `success` boolean and an `error-codes` list. So the transport, the
 * JSON handling and the error-code classification live here once.
 *
 * What does NOT live here is the part each vendor does differently — the score,
 * and whether it exists at all. That is the trap this class is arranged to make
 * impossible to fall into; see scoreThreshold() and the subclasses.
 *
 * Endpoints and field names are taken from each vendor's own server-side
 * validation documentation, not from memory.
 */
abstract class SiteVerifyGateway implements CaptchaProvider
{
    public function __construct(
        protected readonly HttpClientPort $http,
        protected readonly string $secret,
        protected readonly int $timeout = 10,
    ) {}

    abstract public function name(): string;

    abstract public function tokenField(): string;

    /** The vendor's siteverify URL. */
    abstract protected function endpoint(): string;

    /**
     * The minimum score to accept, or null when this vendor does not score.
     *
     * Returning a number here when the vendor sends no score would reject every
     * visitor; returning null when it does send one accepts every bot that can
     * fetch a token. Both failures are silent, which is why this is abstract
     * rather than a shared default.
     */
    abstract protected function scoreThreshold(): ?float;

    /**
     * Extra form fields for this vendor, e.g. hCaptcha's `sitekey`.
     *
     * @return array<string, string>
     */
    protected function extraFields(): array
    {
        return [];
    }

    public function verify(string $token, ?string $remoteIp = null, ?string $expectedAction = null): CaptchaVerdict
    {
        if (trim($token) === '') {
            // Not a failed challenge: no challenge was answered. Usually the
            // widget was not rendered, or the field name on the page does not
            // match what the vendor writes.
            return CaptchaVerdict::missing($this->name());
        }

        $form = ['secret' => $this->secret, 'response' => $token] + $this->extraFields();

        if ($remoteIp !== null && $remoteIp !== '') {
            $form['remoteip'] = $remoteIp;
        }

        try {
            $response = $this->http->request('POST', $this->endpoint(), [
                'form'    => $form,
                'headers' => ['Accept' => 'application/json'],
                'timeout' => $this->timeout,
                // One attempt. A token is SINGLE-USE at every vendor here, so a
                // retry of a request the vendor already processed comes back as
                // `timeout-or-duplicate` — turning a transient network blip into
                // what looks like a replay attack against a real visitor.
                'retry'   => 0,
            ]);
        } catch (\Throwable $e) {
            return CaptchaVerdict::unavailable($this->name(), 'could not reach the verifier: ' . $e->getMessage());
        }

        $payload = $response->json();

        if (!\is_array($payload)) {
            return CaptchaVerdict::unavailable(
                $this->name(),
                'HTTP ' . $response->status() . ' with a body that is not JSON',
            );
        }

        /** @var list<string> $codes */
        $codes = array_values(array_filter(
            (array) ($payload['error-codes'] ?? []),
            static fn (mixed $c): bool => \is_string($c),
        ));

        // Classified BEFORE success is read, because a wrong secret and a failed
        // challenge both arrive as success:false and they are opposite problems.
        if ($this->isSecretProblem($codes)) {
            return CaptchaVerdict::misconfigured(
                $this->name(),
                $codes,
                'the server-side secret is missing or wrong — this rejects every visitor, '
                . 'and is a deployment problem rather than a failed challenge',
            );
        }

        if ($this->isReplay($codes)) {
            return CaptchaVerdict::replayed($this->name(), $codes);
        }

        if ($this->isMissing($codes)) {
            return CaptchaVerdict::missing($this->name(), $codes);
        }

        if (($payload['success'] ?? false) !== true) {
            return CaptchaVerdict::failed($this->name(), $codes, $this->readScore($payload));
        }

        $action   = \is_string($payload['action'] ?? null) ? $payload['action'] : null;
        $hostname = \is_string($payload['hostname'] ?? null) ? $payload['hostname'] : null;
        $score    = $this->readScore($payload);

        // A token minted for one action must not be spendable on another: a
        // token harvested from a public 'newsletter' widget would otherwise
        // satisfy the captcha on 'delete-account'. Only checked when the caller
        // asked for an action AND the vendor echoed one, because reCAPTCHA v2
        // and a Turnstile widget with no action configured send none.
        if ($expectedAction !== null && $action !== null && !hash_equals($expectedAction, $action)) {
            return CaptchaVerdict::failed(
                $this->name(),
                $codes,
                $score,
                "the token was minted for action [{$action}] but this route expects [{$expectedAction}]",
            );
        }

        $threshold = $this->scoreThreshold();

        if ($threshold !== null && $score !== null && $score < $threshold) {
            return CaptchaVerdict::failed(
                $this->name(),
                $codes,
                $score,
                sprintf('score %.2f is below the threshold %.2f', $score, $threshold),
            );
        }

        return CaptchaVerdict::passed($this->name(), $score, $action, $hostname);
    }

    public function describe(): string
    {
        $threshold = $this->scoreThreshold();

        return sprintf(
            '%s, secret %s%s',
            $this->name(),
            $this->secret === '' ? 'UNSET' : 'set (' . \strlen($this->secret) . ' chars)',
            $threshold === null ? '' : ', score threshold ' . number_format($threshold, 2),
        );
    }

    /**
     * @param array<array-key, mixed> $payload
     */
    protected function readScore(array $payload): ?float
    {
        $score = $payload['score'] ?? null;

        // Absent means "this vendor or widget type does not score", NOT zero.
        return \is_int($score) || \is_float($score) ? (float) $score : null;
    }

    /**
     * Codes meaning the token was already spent or has expired.
     *
     * Every code below is taken from the vendor's own published list. Note
     * `invalid-input-response` is NOT here: that is a malformed token, which is
     * a failure, not a token that needs replacing.
     *
     * `timeout-or-duplicate` is Cloudflare's and Google's single name for two
     * situations at once — the vendor cannot tell an attacker replaying a
     * captured token from a visitor who resubmitted a form after a validation
     * error with the same token still in the field. hCaptcha splits them into
     * `expired-input-response` and `already-seen-response`. All three mean the
     * same thing to a caller: the widget must mint a new token.
     *
     * @param list<string> $codes
     */
    protected function isReplay(array $codes): bool
    {
        foreach ($codes as $code) {
            if (\in_array($code, [
                'timeout-or-duplicate',     // Turnstile, reCAPTCHA
                'expired-input-response',   // hCaptcha
                'already-seen-response',    // hCaptcha
            ], true)) {
                return true;
            }
        }

        return false;
    }

    /**
     * Codes meaning the OPERATOR is wrong, not the visitor.
     *
     * @param list<string> $codes
     */
    protected function isSecretProblem(array $codes): bool
    {
        foreach ($codes as $code) {
            if (\in_array($code, [
                'missing-input-secret',
                'invalid-input-secret',
                'sitekey-secret-mismatch',  // hCaptcha: the key pair do not belong together
                'not-using-dummy-passcode', // hCaptcha: a test sitekey without its test secret
            ], true)) {
                return true;
            }
        }

        return false;
    }

    /**
     * The vendor says no token reached it.
     *
     * Reported separately because an empty token is already caught before the
     * request; seeing this code back means something stripped the field in
     * transit, which is neither a bot nor a bad secret.
     *
     * @param list<string> $codes
     */
    protected function isMissing(array $codes): bool
    {
        return \in_array('missing-input-response', $codes, true);
    }
}
