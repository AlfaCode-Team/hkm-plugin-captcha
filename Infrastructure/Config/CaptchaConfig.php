<?php

declare(strict_types=1);

namespace Plugins\Captcha\Infrastructure\Config;

/**
 * Everything this plugin reads from the environment, read ONCE.
 *
 * Every key here is declared in module.json `config[]`, or the boot fails.
 */
final readonly class CaptchaConfig
{
    private function __construct(
        public string $provider,
        public ?string $secret,
        public ?string $siteKey,
        public float $scoreThreshold,
        public int $timeout,
        public bool $failOpen,
        public bool $sendIp,
        public ?string $denyMessage,
    ) {}

    public static function fromEnv(): self
    {
        return new self(
            // 'disabled' and not a real provider. Installing a plugin without
            // configuring it must not block every protected route, and the first
            // symptom of that would be a sign-up form nobody can submit.
            provider:       strtolower(trim((string) env('CAPTCHA_PROVIDER', 'disabled'))) ?: 'disabled',
            secret:         self::stringOrNull(env('CAPTCHA_SECRET')),
            siteKey:        self::stringOrNull(env('CAPTCHA_SITE_KEY')),
            scoreThreshold: self::threshold(env('CAPTCHA_SCORE_THRESHOLD')),
            timeout:        max(1, (int) env('CAPTCHA_TIMEOUT', 10)),
            // FAIL CLOSED by default. See CaptchaService for the argument; it is
            // the opposite of the kernel's WafLayer and deliberately so.
            failOpen:       (bool) filter_var(env('CAPTCHA_FAIL_OPEN', false), FILTER_VALIDATE_BOOL),
            // OPT-IN. Behind a CDN or load balancer the address this process
            // sees is the proxy's, and every vendor here treats a remoteip that
            // disagrees with the token's origin as a reason to fail — so sending
            // the wrong one makes verification worse, not better. hCaptcha even
            // has a dedicated `invalid-remoteip` code for it.
            sendIp:         (bool) filter_var(env('CAPTCHA_SEND_IP', false), FILTER_VALIDATE_BOOL),
            denyMessage:    self::stringOrNull(env('CAPTCHA_DENY_MESSAGE')),
        );
    }

    public static function of(
        string $provider = 'disabled',
        ?string $secret = null,
        ?string $siteKey = null,
        float $scoreThreshold = 0.5,
        int $timeout = 10,
        bool $failOpen = false,
        bool $sendIp = false,
        ?string $denyMessage = null,
    ): self {
        return new self($provider, $secret, $siteKey, $scoreThreshold, $timeout, $failOpen, $sendIp, $denyMessage);
    }

    public function isDisabled(): bool
    {
        return $this->provider === 'disabled' || $this->provider === '' || $this->provider === 'off';
    }

    /**
     * Clamped to 0.0–1.0, because that is the only range any vendor emits.
     *
     * A threshold outside it is silently useless in one direction or the other:
     * above 1.0 nothing ever passes, below 0.0 everything does. Clamping with a
     * sane default beats both.
     */
    private static function threshold(mixed $value): float
    {
        if ($value === null || $value === '') {
            return 0.5;
        }

        return max(0.0, min(1.0, (float) $value));
    }

    private static function stringOrNull(mixed $value): ?string
    {
        if (!\is_string($value)) {
            return $value === null ? null : (string) $value;
        }

        $trimmed = trim($value);

        return $trimmed === '' ? null : $trimmed;
    }
}
