<?php

declare(strict_types=1);

namespace Plugins\Captcha\Infrastructure\Http\Stages;

use AlfacodeTeam\PhpServicePlatform\Kernel\Http\Request;
use AlfacodeTeam\PhpServicePlatform\Kernel\Http\Response;
use AlfacodeTeam\PhpServicePlatform\Kernel\Pipelines\Http\Contracts\HttpStageContract;
use Plugins\Captcha\API\Contracts\CaptchaVerifierContract;
use Plugins\Captcha\Application\Services\CaptchaService;
use Plugins\Captcha\Domain\CaptchaVerdict;

/**
 * The `captcha` route filter.
 *
 * A route opts in from its own manifest, and the action it expects is the
 * filter argument:
 *
 *   { "method": "POST", "path": "/register", "handler": "…@store",
 *     "filters": ["captcha:register"] }
 *
 * Naming the action matters. Every scored provider echoes back the action the
 * token was minted for, and without this check a token harvested from a public
 * widget — a newsletter box on the marketing site — satisfies the captcha on
 * `/password/reset`. With it, the token is only spendable where it was minted.
 *
 * Registered as a FILTER, never as a global hook. Both would make it run twice
 * per request, and a captcha token is single-use: the second verification comes
 * back `timeout-or-duplicate` and every protected request fails.
 */
final class VerifyCaptchaStage implements HttpStageContract
{
    public function handle(Request $request, callable $next): Response
    {
        // Only when the matched route asked for it. A filter stage runs at the
        // after.load position for every request whose route names the alias.
        if (!\in_array('captcha', (array) $request->attribute('active_filters'), true)) {
            return $next($request);
        }

        $verifier = $this->verifier($request);

        if ($verifier === null) {
            // The route declared a filter whose plugin is not wired. Refusing is
            // the only safe answer: passing would leave the route looking
            // protected while nothing checked it.
            return Response::forbidden('Verification is unavailable.');
        }

        $args   = (array) ($request->attribute('filter_args')['captcha'] ?? []);
        $action = isset($args[0]) && trim((string) $args[0]) !== '' ? trim((string) $args[0]) : null;

        $verdict = $verifier->verify(
            $this->token($request, $verifier->tokenField()),
            $request->ip(),
            $action,
        );

        if ($verifier->allows($verdict)) {
            // Attached so a controller or audit listener can record the score
            // without verifying again — which it could not do anyway, the token
            // having been spent.
            return $next($request->withAttribute('captcha_verdict', $verdict));
        }

        return $this->deny($verdict, $verifier);
    }

    /**
     * Where the token is looked for, in order.
     *
     * The vendor's own field name comes first so a page using the standard
     * widget markup needs no extra wiring; then a neutral name for a form that
     * would rather not encode its provider; then a header, which is how a
     * JSON/API client sends it.
     */
    private function token(Request $request, string $field): string
    {
        foreach ([$field, 'captcha-response', 'captcha_token'] as $candidate) {
            $value = $request->input($candidate);

            if (\is_string($value) && trim($value) !== '') {
                return trim($value);
            }
        }

        $header = $request->header('X-Captcha-Token');

        return $header === null ? '' : trim($header);
    }

    /**
     * 422 for an outcome the visitor can fix, 403 for one they cannot.
     *
     * This is not cosmetic. A single-use token resubmitted after a server-side
     * validation error is the single commonest failure on a real form, and it is
     * not an attack: answering 403 "Forbidden" leaves the person stuck on a page
     * that has already rejected them once, while a 422 naming the token field
     * lets the form re-render with the message beside the widget, which is where
     * they need to look.
     */
    private function deny(CaptchaVerdict $verdict, CaptchaVerifierContract $verifier): Response
    {
        $message = $verifier instanceof CaptchaService
            ? $verifier->denyMessage($verdict)
            : 'Verification failed. Please try again.';

        if ($verdict->outcome->isRetryable()) {
            return Response::unprocessable([$verifier->tokenField() => $message], $message);
        }

        return Response::forbidden($message);
    }

    /**
     * Resolved from the REQUEST container, not constructor DI.
     *
     * Filter stages are built with `new` from the CoreContainer, so a
     * constructor dependency on a request-scoped binding would never be
     * injected. Same reasoning as the SecurityFilters stages.
     */
    private function verifier(Request $request): ?CaptchaVerifierContract
    {
        $container = $request->container();

        if ($container === null || !$container->has(CaptchaVerifierContract::class)) {
            return null;
        }

        $verifier = $container->make(CaptchaVerifierContract::class);

        return $verifier instanceof CaptchaVerifierContract ? $verifier : null;
    }
}
