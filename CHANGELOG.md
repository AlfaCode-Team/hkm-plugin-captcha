# Changelog

All notable changes to `hkm-plugin-captcha` are documented here. The format is
based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this
project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- **First release: server-side captcha verification behind one contract.**
  Cloudflare Turnstile, Google reCAPTCHA (v2 and v3) and hCaptcha, over each
  vendor's siteverify endpoint through `HttpClientPort` — no SDK. Solves
  `captcha.verification` and publishes the `captcha` route filter.

- **One gateway that is correct for reCAPTCHA v2 *and* v3.** The two versions
  fail in opposite, silent directions: on v3 Google returns `success: true` for
  any valid unspent token including one a bot obtained, putting the judgement in
  `score`, so reading `success` alone accepts every bot; on v2 there is no score
  at all, so *requiring* one rejects every human. A score is therefore compared
  only when the vendor sends one, and a missing score stays `null` rather than
  becoming `0.0`. Both directions are pinned by tests.

- **The filter argument is the expected action** — `"filters": ["captcha:register"]`.
  Every provider supporting actions echoes back the one its token carries, and
  without the check a token harvested from a public widget satisfies the captcha
  on an unrelated route.

- **Six outcomes instead of a boolean**, because four of them are not "this is a
  bot". A spent token (`Replayed`) and an absent one (`Missing`) answer **422**
  naming the token field, so a form can re-render with the message beside the
  widget — the commonest real cause is a person resubmitting after a validation
  error with the same single-use token, and a 403 saying "Forbidden" leaves them
  stuck. A wrong secret (`Misconfigured`) is reported separately and logged at
  error, because it rejects *every* visitor and presenting it as a failed
  challenge sends the team looking at the widget. Error-code classification is
  taken from each vendor's published list.

- **Fails closed by default, unlike the kernel's `WafLayer`.** The WAF inspects
  every request, so failing closed takes the application down; this guards named
  routes that carry the filter precisely because they are under attack, and
  opening them during an outage hands a bypass to anyone who can cause one.
  `CAPTCHA_FAIL_OPEN` exists because the trade is real. A misconfigured secret
  always blocks and is **not** covered by the flag — it is not an outage, and
  excusing it would let a typo silently disable the protection.

- **`CAPTCHA_SEND_IP` is opt-in.** Behind a CDN the address this process sees is
  the proxy's, and every vendor treats a `remoteip` disagreeing with the token's
  origin as a reason to fail — hCaptcha has a dedicated `invalid-remoteip` code.
  Sending the wrong address makes verification worse.

- **`disabled` is the default and says so.** Installing the plugin without
  configuring it must not block every protected route, but a filter that
  silently passes everything is worse than no filter — so it warns once per
  process and `captcha:status` prints `NOTHING IS VERIFIED`.

- **hCaptcha's `sitekey` is sent when configured**, which hCaptcha documents as
  preventing a token issued for one sitekey being redeemed against another.

### Fixed during development

- **`invalid-input-response` was classified as a replay.** It is a malformed
  token, which is a failure — asking the visitor for a fresh one achieves
  nothing. The genuine replay codes are `timeout-or-duplicate` (Turnstile,
  reCAPTCHA) and hCaptcha's `expired-input-response` / `already-seen-response`.

- **Two hCaptcha error codes were asserted without being verified.** Replaced
  with the published list, which also added `not-using-dummy-passcode` and
  confirmed `sitekey-secret-mismatch`.

- **A `Missing` verdict dropped the vendor's error codes**, so a log line could
  not distinguish "no token reached this process" from "the vendor reported the
  absence". Caught by this plugin's own test suite.
