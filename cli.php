<?php

declare(strict_types=1);

require __DIR__ . "/vendor/autoload.php";
require __DIR__ . "/vendor/myphps/myphp/base.php";

//在项目所有目录执行此文件 自动获取项目路径 未在
if (empty($_SERVER['argv']) || count($_SERVER['argv']) == 1) {
    die('no argv');
}

if (!IS_CLI) {
    die('no cli');
}
\myphp\Log::Dir('cli');
echo implode(" ", $_SERVER['argv']).PHP_EOL;
$a = 'cli'.ucfirst($_SERVER['argv'][1]);
$params = array_slice($_SERVER['argv'], 2);
cliRun($a, $params);

//脚本命令处理
function cliRun($a, $params)
{
    try {
        if (!function_exists($a)) {
            throw new \Exception($a .' not exists');
        }
        $ret = call_user_func_array($a, $params);
        if (is_bool($ret)) {
            echo $ret ? 'ok' : 'fail:'.\myphp\Tool::err();
        } elseif (is_scalar($ret)) {
            echo $ret;
        } elseif ($ret !== null) {
            echo toJson($ret);
        }
    } catch (\Throwable $e) {
        echo $e->getMessage();
    }
    echo PHP_EOL;
}

/**
 * 生成phar文件 my.phar 仅用于常驻内存模式下运行: php my.phar
 * php cli.php phar
 * php -d phar.readonly=0 cli.php phar   使用 -d 参数来临时修改 phar.readonly 设置
 * @param string $sigName
 * @param string $private_key_file
 */
function cliPhar(string $sigName = 'sha256', string $private_key_file = '')
{
    if (!is_dir(__DIR__ . '/dist/web')) {
        mkdir(__DIR__ . '/dist/web', 0755, true);
    }
    $pharFile = __DIR__ . '/dist/socks5.phar';
    if (file_exists($pharFile)) {
        unlink($pharFile);
    }

    $sigTypeMap = ['md5' => Phar::MD5, 'sha1' => Phar::SHA1, 'sha256' => Phar::SHA256, 'sha512' => Phar::SHA512, 'openssl' => Phar::OPENSSL];
    $sigType = $sigTypeMap[$sigName] ?? Phar::SHA256;

    //github/|/.idea/|/.git
    $exRegex = '#^(?!.*(\.log|\.md|\.pid|\.sh|\.gitignore|runLock|composer.lock|composer.json|/.github/|/.idea/|/.git/|/.claude/|/.kiro/|/.vscode/|/ws-relay-client/|/tests/|/runtime/|/log/|/vendor/bin/|/build/|/dist/|/web/))(.*)$#';
    $phar = new Phar($pharFile, 0, 'my');
    $phar->startBuffering();

    if ($sigType === Phar::OPENSSL) {
        if (!file_exists($private_key_file)) {
            throw new RuntimeException("使用'Phar::OPENSSL'签名需要提供私钥文件");
        }
        $private = openssl_get_privatekey(file_get_contents($private_key_file));
        $pkey = '';
        openssl_pkey_export($private, $pkey);
        $phar->setSignatureAlgorithm($sigType, $pkey);
    } else {
        $phar->setSignatureAlgorithm($sigType);
    }

    $phar->buildFromDirectory(__DIR__, $exRegex);

    $exFiles = [
        //'vendor/myphps/myphp/inc/ggbi.ttf',
        'vendor/myphps/myphp/inc/fzxbsjw.ttf',
        '.gitattributes',
        '.php-cs-fixer.cache',
        '.php-cs-fixer.dist.php',
        'config.ini',
        'php.ini',
        'phpacker.json',
        'phpstan.neon.dist',
        'README.md'
    ];
    foreach ($exFiles as $file) {
        if ($phar->offsetExists($file)) {
            $phar->delete($file);
        }
    }

    echo '开始生成Phar',PHP_EOL;
    //在直接使用my.phar时直接执行app.php
    $phar->setStub("#!/usr/bin/env php
<?php
Phar::mapPhar('my');
require 'phar://my/socks5.php';
__HALT_COMPILER();
");

    $phar->stopBuffering();
    unset($phar);

    //复制配置文件
    copy(__DIR__ . '/config.ini', __DIR__ . '/dist/config.ini');

    echo 'Phar生成完成',PHP_EOL;
}
