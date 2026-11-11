# hkm-plugin-captcha

> HKM Kernel plugin — provides **`captcha.verification`** and the `captcha` route filter.
> Part of the [HKM Kernel](https://github.com/AlfaCode-Team/hkm-kernel) Gated Demand Architecture framework.

![PHP](https://img.shields.io/badge/PHP-8.4%2B-777bb4)

Cloudflare Turnstile, Google reCAPTCHA (v2 **and** v3) and hCaptcha behind one
contract, verified server-side through the kernel's `HttpClientPort`. No SDK.

## Use it from a route, not from code

```jsonc
{ "method": "POST", "path": "/register", "handler": "…@store",
  "filters": ["captcha:register"] }
```

The filter argument is the **action** the token must have been minted for, and
naming it matters. Every provider that supports actions echoes back the one the
token carries; without the check, a token harvested from a public widget — a
newsletter box on the marketing site — satisfies the captcha on
`/password/reset`. With it, a token is only spendable where it was minted.

`CaptchaVerifierContract` exists for the cases a filter cannot express — a
captcha required only on one branch of a service, or a verdict to record rather
than enforce.

## Configuration

| Variable | Default | Notes |
| --- | --- | --- |
| `CAPTCHA_PROVIDER` | `disabled` | `turnstile`, `recaptcha`, `hcaptcha`, or `disabled`. An unknown name **fails** |
| `CAPTCHA_SECRET` | — | The **server-side** secret, not the public site key that goes in the page |
| `CAPTCHA_SITE_KEY` | — | hCaptcha only: pins the sitekey so a token from another one is refused |
| `CAPTCHA_SCORE_THRESHOLD` | `0.5` | reCAPTCHA v3 only. Clamped to 0.0–1.0 |
| `CAPTCHA_TIMEOUT` | `10` | Seconds |
| `CAPTCHA_FAIL_OPEN` | `false` | Whether a provider outage lets requests through |
| `CAPTCHA_SEND_IP` | `false` | Opt-in — see below |
| `CAPTCHA_DENY_MESSAGE` | — | Overrides every denial message, so this plugin needs no i18n dependency |

**`disabled` is the default**, and it passes everything. Installing the plugin
without configuring it must not block every protected route — the first symptom
would be a sign-up form nobody can submit. But a filter that silently passes
everything is worse than no filter, because the route looks protected in
`module.json` and in review, so a disabled provider **logs a warning once per
process** and `captcha:status` says `NOTHING IS VERIFIED` in those words.

## Scores: the trap that runs both ways

This is the part worth reading, because both mistakes are silent and opposite.

**On reCAPTCHA v3 there is no pass or fail.** Google returns `success: true` for
any structurally valid, unspent token — *including one a bot obtained* — and puts
the judgement in `score`, 0.0 to 1.0. A verifier that reads `success` alone
accepts every bot while appearing to work perfectly.

**On reCAPTCHA v2 there is no score**, because the visitor solved a challenge and
`success` is the answer. A verifier that *requires* a score rejects every human
on the site. Appwrite's own implementation does exactly this
(`packages/abuse/src/ReCaptcha.php` returns false unless a score is present and
above the threshold) — correct for v3, wrong for v2.

The resolution is to compare a score **only when the vendor sends one**. One
gateway is therefore correct for both versions, and neither configuration can be
broken by picking the wrong class. Turnstile and non-Enterprise hCaptcha send no
score at all, so their threshold is `null`: applying one would read the absence
as `0.0` and reject everyone. **A missing score is never 0.**

Both directions are pinned by tests, and confirmed load-bearing by reverting
them.

## Six outcomes, because one 403 is wrong

A bool is not enough. Four of these are **not** "this is a bot", and answering
them all identically either blocks real people or hides a deployment fault.

| Outcome | Means | Response |
| --- | --- | --- |
| `Passed` | Verified | continue |
| `Failed` | The provider says no. **The only one that means "bot"** | 403 |
| `Replayed` | The token was already spent or expired | **422** naming the token field |
| `Missing` | No token arrived — usually front-end wiring | **422** |
| `Unavailable` | The provider could not be reached | 403, or pass with `CAPTCHA_FAIL_OPEN` |
| `Misconfigured` | Wrong or missing **secret** | 403 always, and logged at error |

`Replayed` is the one people get wrong. Every provider here issues **single-use**
tokens, and the vendor cannot tell an attacker replaying a captured token from a
real person who resubmitted a form after a validation error with the same token
still in the field — Cloudflare's own name for it, `timeout-or-duplicate`, is
honest about being two things at once. So the response is a 422 that names the
token field, letting the form re-render with the message beside the widget, and
the text never says "bot". A 403 "Forbidden" would leave that person stuck on a
page that had already rejected them once.

`Misconfigured` is reported separately for the opposite reason: a wrong secret
rejects *every* visitor, and presenting that as a failed challenge sends the
whole team looking at the widget.

Error-code classification is taken from each vendor's published list, including
hCaptcha's distinct `expired-input-response` and `already-seen-response`.
`invalid-input-response` is a **failure**, not a replay — it is a malformed
token, and nothing is gained by asking for another one.

## Fail closed, unlike the kernel's WAF

`CAPTCHA_FAIL_OPEN` defaults to **false**, which is the opposite of `WafLayer`,
and deliberate:

- the WAF inspects **every** request, so failing closed takes the whole
  application down — "a firewall whose cache outage takes the site down has
  become the attack";
- this guards a handful of named routes, and they carry the filter precisely
  *because* they are under attack. Opening them during an outage removes the
  protection at the moment it is most likely being probed, and an attacker who
  can cause the outage gets the bypass.

The flag exists because the trade is real: an operator running a sign-up funnel
may legitimately prefer the bots to the lost conversions.

**A misconfigured secret always blocks and is not covered by the flag.** It is
not an outage — it is entirely within the operator's control, and opening the
gate on it would mean a mistyped secret silently disabled the protection for as
long as nobody noticed.

## Where the token is read from, and why the IP is opt-in

In order: the vendor's own field (`cf-turnstile-response`, `g-recaptcha-response`,
`h-captcha-response`), then `captcha-response` / `captcha_token`, then the
`X-Captcha-Token` header for JSON clients.

`CAPTCHA_SEND_IP` is **off** by default. Behind a CDN or load balancer the
address this process sees is the proxy's, and every vendor here treats a
`remoteip` that disagrees with the token's origin as a reason to fail — hCaptcha
has a dedicated `invalid-remoteip` code. Sending the wrong address makes
verification worse, not better. Turn it on only where the client IP reaching PHP
is genuinely the visitor's.

## Registered as a filter, never also as a hook

Doing both would run the stage twice per request, and the token is single-use:
the second verification returns `timeout-or-duplicate` and **every** protected
request fails.

## Testing

```bash
HKM_KERNEL_PATH=/path/to/hkm-kernel vendor/bin/phpunit
```

## Verified / not verified

**Verified**: 53 tests, 120 assertions. `ground check --strict` clean. Endpoints
and field names asserted against each vendor's published siteverify reference;
every documented error code asserted into its bucket. Three behaviours confirmed
load-bearing by reverting them: enforcing the v3 score (bots would pass),
*not* requiring a score (v2 humans would be rejected), and the action binding
(a token would be spendable across routes).

**Not verified:**

- **No request has ever reached Cloudflare, Google or hCaptcha.** A valid token
  can only be minted by a real widget in a real browser, and none of these
  vendors has an equivalent of FCM's `validate_only`, so there is no live check
  a test suite can make. Every behaviour above comes from the published
  references, and a misreading of one is exactly what these tests cannot catch.
- **No secret has been authenticated**, so `Misconfigured` has been exercised
  only from a scripted response, never from a real rejection.
- **The route filter has never run in a pipeline.** `VerifyCaptchaStage` is
  covered by reading, not by a request: its `active_filters` / `filter_args`
  handling follows the SecurityFilters stages, but no HTTP request has passed
  through it. This is the largest gap in the plugin.
- **Enterprise features are untouched** — hCaptcha scores, Turnstile's
  `metadata.ephemeral_id`, Turnstile's `idempotency_key`.
- **Nothing about load**: no concurrency, no rate limits, no behaviour under a
  vendor's throttling.

## License

MIT — see [LICENSE](LICENSE).
