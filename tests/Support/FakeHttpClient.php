<?php

declare(strict_types=1);

namespace Tests\Plugins\Captcha\Support;

use AlfacodeTeam\PhpServicePlatform\Kernel\Ports\HttpClientPort;
use AlfacodeTeam\PhpServicePlatform\Kernel\Ports\HttpClientResponse;
use AlfacodeTeam\PhpServicePlatform\Kernel\Ports\PendingRequestContract;

/**
 * A scripted HttpClientPort that records what was asked of it.
 *
 * The gateway tests assert the EXACT request built — endpoint and form field
 * names — against each vendor's published siteverify contract, because that is
 * the half of the behaviour this plugin owns. A wrong endpoint or field name
 * reads to everyone involved as "the captcha is failing", and sends them
 * looking at their keys.
 */
final class FakeHttpClient implements HttpClientPort
{
    /** @var list<array{method: string, url: string, options: array<string, mixed>}> */
    public array $requests = [];

    /** @var list<HttpClientResponse|\Throwable> */
    private array $script = [];

    public function willReturn(int $status, string $body = '', array $headers = []): self
    {
        $this->script[] = new HttpClientResponse($status, $body, $headers);

        return $this;
    }

    public function willReturnJson(int $status, array $payload): self
    {
        return $this->willReturn($status, (string) json_encode($payload));
    }

    public function willThrow(\Throwable $e): self
    {
        $this->script[] = $e;

        return $this;
    }

    public function request(string $method, string $url, array $options = []): HttpClientResponse
    {
        $this->requests[] = ['method' => $method, 'url' => $url, 'options' => $options];

        $next = array_shift($this->script);

        if ($next === null) {
            // Loud, not a default response. A test whose transport made an
            // unexpected extra call should fail on that fact rather than be
            // handed an empty 200 and carry on.
            throw new \LogicException(sprintf(
                'FakeHttpClient had nothing scripted for %s %s (call #%d).',
                $method,
                $url,
                \count($this->requests),
            ));
        }

        if ($next instanceof \Throwable) {
            throw $next;
        }

        return $next;
    }

    public function get(string $url, array $query = []): HttpClientResponse
    {
        return $this->request('GET', $url, $query === [] ? [] : ['query' => $query]);
    }

    public function post(string $url, array $data = []): HttpClientResponse
    {
        return $this->request('POST', $url, $data === [] ? [] : ['json' => $data]);
    }

    public function put(string $url, array $data = []): HttpClientResponse
    {
        return $this->request('PUT', $url, $data === [] ? [] : ['json' => $data]);
    }

    public function patch(string $url, array $data = []): HttpClientResponse
    {
        return $this->request('PATCH', $url, $data === [] ? [] : ['json' => $data]);
    }

    public function delete(string $url, array $data = []): HttpClientResponse
    {
        return $this->request('DELETE', $url, $data === [] ? [] : ['json' => $data]);
    }

    public function pending(): PendingRequestContract
    {
        throw new \LogicException('FakeHttpClient does not provide the fluent builder; nothing here uses it.');
    }

    /** @return array{method: string, url: string, options: array<string, mixed>} */
    public function lastRequest(): array
    {
        $last = $this->requests[\count($this->requests) - 1] ?? null;

        if ($last === null) {
            throw new \LogicException('No request was made.');
        }

        return $last;
    }

    /** @return array<string, mixed> */
    public function lastForm(): array
    {
        $form = $this->lastRequest()['options']['form'] ?? [];

        return \is_array($form) ? $form : [];
    }

    /** @return array<string, string> */
    public function lastHeaders(): array
    {
        $headers = $this->lastRequest()['options']['headers'] ?? [];

        return \is_array($headers) ? $headers : [];
    }
}
