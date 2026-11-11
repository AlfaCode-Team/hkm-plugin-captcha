<?php

declare(strict_types=1);

/**
 * Test bootstrap.
 *
 * Resolves the kernel from `vendor/` when the plugin has been composer-
 * installed, and otherwise from a local checkout, so the plugin is runnable
 * before it has ever been installed anywhere.
 *
 * Order, most specific first:
 *   1. HKM_KERNEL_PATH          — an explicit checkout
 *   2. vendor/autoload.php      — composer-installed (CI)
 *   3. ../../../PHP             — the conventional workspace layout
 */

$pluginRoot = \dirname(__DIR__);

spl_autoload_register(static function (string $class) use ($pluginRoot): void {
    // Test support classes first: Tests\Plugins\Captcha\ is a PREFIX of nothing
    // else, but Plugins\Captcha\ is not a prefix of it, so the order below would
    // otherwise never reach them.
    $map = [
        'Tests\\Plugins\\Captcha\\' => $pluginRoot . '/tests/',
        'Plugins\\Captcha\\'        => $pluginRoot . '/',
    ];

    foreach ($map as $prefix => $base) {
        if (!str_starts_with($class, $prefix)) {
            continue;
        }

        $relative = substr($class, \strlen($prefix));
        $path     = $base . str_replace('\\', '/', $relative) . '.php';

        if (is_file($path)) {
            require_once $path;
        }

        return;
    }
});

$kernelRoot = getenv('HKM_KERNEL_PATH') ?: null;

if ($kernelRoot === null && is_file($pluginRoot . '/vendor/autoload.php')) {
    require_once $pluginRoot . '/vendor/autoload.php';

    if (interface_exists(\AlfacodeTeam\PhpServicePlatform\Kernel\Ports\HttpClientPort::class)) {
        return;
    }

    fwrite(STDERR, <<<'TXT'

        The installed kernel does not provide HttpClientPort.
        To run the tests against a local kernel checkout instead:

            HKM_KERNEL_PATH=/path/to/hkm-kernel vendor/bin/phpunit


        TXT);
    exit(1);
}

$kernelRoot ??= \dirname($pluginRoot, 3) . '/PHP';

if (!is_dir($kernelRoot . '/src/Kernel')) {
    fwrite(STDERR, \sprintf(
        "\nCannot find the kernel. Looked in %s.\nSet HKM_KERNEL_PATH to a checkout, or run"
        . " `composer install`.\n\n",
        $kernelRoot,
    ));
    exit(1);
}

spl_autoload_register(static function (string $class) use ($kernelRoot): void {
    $prefix = 'AlfacodeTeam\\PhpServicePlatform\\';

    if (!str_starts_with($class, $prefix)) {
        return;
    }

    $relative = substr($class, \strlen($prefix));
    $path     = $kernelRoot . '/src/' . str_replace('\\', '/', $relative) . '.php';

    if (is_file($path)) {
        require_once $path;
    }
});

if (is_file($kernelRoot . '/src/Kernel/Support/helpers.php')) {
    require_once $kernelRoot . '/src/Kernel/Support/helpers.php';
}
