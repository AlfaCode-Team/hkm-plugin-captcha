<?php

declare(strict_types=1);

namespace Plugins\Captcha\Domain;

/**
 * One verification's result, with enough detail to act on it.
 */
final readonly class CaptchaVerdict
{
    /**
     * @param list<string> $errorCodes the provider's own codes, verbatim
     * @param float|null   $score      0.0–1.0 where the provider gives one.
     *                                 NULL IS NOT ZERO: reCAPTCHA v2, Turnstile
     *                                 and non-Enterprise hCaptcha return no
     *                                 score at all, and defaulting a missing
     *                                 score to 0 rejects every human on the site.
     * @param string|null  $action     the action the token was minted for, where
     *                                 the provider echoes it back
     */
    private function __construct(
        public CaptchaOutcome $outcome,
        public string $provider,
        public array $errorCodes = [],
        public ?float $score = null,
        public ?string $action = null,
        public ?string $hostname = null,
        public ?string $detail = null,
    ) {}

    public static function passed(
        string $provider,
        ?float $score = null,
        ?string $action = null,
        ?string $hostname = null,
    ): self {
        return new self(CaptchaOutcome::Passed, $provider, score: $score, action: $action, hostname: $hostname);
    }

    /** @param list<string> $errorCodes */
    public static function failed(string $provider, array $errorCodes = [], ?float $score = null, ?string $detail = null): self
    {
        return new self(CaptchaOutcome::Failed, $provider, $errorCodes, $score, detail: $detail);
    }

    /** @param list<string> $errorCodes */
    public static function replayed(string $provider, array $errorCodes = []): self
    {
        return new self(CaptchaOutcome::Replayed, $provider, $errorCodes);
    }

    /**
     * @param list<string> $errorCodes empty when no token reached this process
     *                                 at all, and populated when the VENDOR
     *                                 reported the absence — the codes are the
     *                                 only way to tell those two apart in a log
     */
    public static function missing(string $provider, array $errorCodes = []): self
    {
        return new self(CaptchaOutcome::Missing, $provider, $errorCodes);
    }

    public static function unavailable(string $provider, string $detail): self
    {
        return new self(CaptchaOutcome::Unavailable, $provider, detail: $detail);
    }

    /** @param list<string> $errorCodes */
    public static function misconfigured(string $provider, array $errorCodes, string $detail): self
    {
        return new self(CaptchaOutcome::Misconfigured, $provider, $errorCodes, detail: $detail);
    }

    public function isPass(): bool
    {
        return $this->outcome->isPass();
    }

    /**
     * A line safe to log.
     *
     * Carries no token and no secret. The token is a bearer credential for one
     * verification and the error codes are enough to diagnose without it.
     */
    public function describe(): string
    {
        $parts = [$this->provider, $this->outcome->value];

        if ($this->score !== null) {
            $parts[] = 'score ' . number_format($this->score, 2);
        }

        if ($this->action !== null) {
            $parts[] = 'action ' . $this->action;
        }

        if ($this->errorCodes !== []) {
            $parts[] = '[' . implode(' ', $this->errorCodes) . ']';
        }

        if ($this->detail !== null) {
            $parts[] = $this->detail;
        }

        return implode(' — ', $parts);
    }
}
