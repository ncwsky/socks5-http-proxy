#!/usr/bin/env php
<?php
define('RUN_DIR', __DIR__);
define('VENDOR_DIR', __DIR__ . '/vendor');
#define('PROC_COUNT', 2); //进程数

require __DIR__. '/vendor/myphps/socks5-http-proxy/socks5.php';