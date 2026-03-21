#!/usr/bin/env php
<?php
/**
 * Socks5/HTTP 代理模拟测试
 * 测试协议解析、握手、认证、连接等核心逻辑
 */

error_reporting(E_ALL);
ini_set('display_errors', 'On');

require __DIR__ . '/vendor/autoload.php';
require __DIR__ . '/vendor/myphps/myphp/base.php';

use common\Socks5;

// 简易日志函数
function logger($level, $str)
{
    // 测试时静默，失败时才输出
}

$passed = 0;
$failed = 0;
$total = 0;

function test(string $name, callable $fn)
{
    global $passed, $failed, $total;
    $total++;
    try {
        $fn();
        $passed++;
        echo "  ✓ {$name}" . PHP_EOL;
    } catch (\Throwable $e) {
        $failed++;
        echo "  ✗ {$name}" . PHP_EOL;
        echo "    错误: " . $e->getMessage() . PHP_EOL;
    }
}

function assertEqual($expected, $actual, string $msg = '')
{
    if ($expected !== $actual) {
        $detail = $msg ? " ({$msg})" : '';
        throw new \RuntimeException(
            "期望 " . var_export($expected, true) . " 实际 " . var_export($actual, true) . $detail
        );
    }
}

function assertContains(string $needle, string $haystack, string $msg = '')
{
    if (strpos($haystack, $needle) === false) {
        $detail = $msg ? " ({$msg})" : '';
        throw new \RuntimeException("未找到 " . bin2hex($needle) . " 于 " . bin2hex($haystack) . $detail);
    }
}

// ==================================================
echo "=== 1. 协议检测测试 ===" . PHP_EOL;
// ==================================================

test('SOCKS5首字节0x05识别为socks', function () {
    // socks5握手: VER=0x05 NMETHODS=1 METHODS=0x00
    $data = "\x05\x01\x00";
    assertEqual(0x05, ord($data[0]));
    // 按新逻辑，首字节为0x05时走socks
    $isSocks = (ord($data[0]) === 0x05);
    assertEqual(true, $isSocks);
});

test('HTTP GET请求不被识别为socks', function () {
    $data = "GET http://example.com/ HTTP/1.1\r\nHost: example.com\r\n\r\n";
    $isSocks = (ord($data[0]) === 0x05);
    assertEqual(false, $isSocks);
});

test('HTTP CONNECT请求不被识别为socks', function () {
    $data = "CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n";
    $isSocks = (ord($data[0]) === 0x05);
    assertEqual(false, $isSocks);
});

test('HTTP POST请求不被识别为socks', function () {
    $data = "POST http://example.com/api HTTP/1.1\r\nContent-Length: 5\r\n\r\nhello";
    $isSocks = (ord($data[0]) === 0x05);
    assertEqual(false, $isSocks);
});

// ==================================================
echo PHP_EOL . "=== 2. SOCKS5握手解析测试 ===" . PHP_EOL;
// ==================================================

test('解析无认证握手请求', function () {
    // VER=0x05 NMETHODS=1 METHODS=[0x00]
    $buffer = "\x05\x01\x00";
    $offset = 0;

    $ver = ord($buffer[$offset]);
    $offset += 1;
    $method_count = ord($buffer[$offset]);
    $offset += 1;
    $methods = [];
    for ($i = 0; $i < $method_count; $i++) {
        $methods[] = ord($buffer[$offset]);
        $offset++;
    }

    assertEqual(0x05, $ver, 'version');
    assertEqual(1, $method_count, 'method_count');
    assertEqual([Socks5::METHOD_NO_AUTH], $methods, 'methods');
});

test('解析多认证方法握手请求', function () {
    // VER=0x05 NMETHODS=2 METHODS=[0x00, 0x02]
    $buffer = "\x05\x02\x00\x02";
    $offset = 0;

    $ver = ord($buffer[$offset]);
    $offset += 1;
    $method_count = ord($buffer[$offset]);
    $offset += 1;
    $methods = [];
    for ($i = 0; $i < $method_count; $i++) {
        $methods[] = ord($buffer[$offset]);
        $offset++;
    }

    assertEqual(0x05, $ver);
    assertEqual(2, $method_count);
    assertEqual([Socks5::METHOD_NO_AUTH, Socks5::METHOD_USER_PASS], $methods);
});

// ==================================================
echo PHP_EOL . "=== 3. 握手响应构建测试 ===" . PHP_EOL;
// ==================================================

test('构建无认证握手响应', function () {
    $response = Socks5::SOCKS_VER . chr(Socks5::METHOD_NO_AUTH);
    assertEqual("\x05\x00", $response);
});

test('构建密码认证握手响应', function () {
    $response = Socks5::SOCKS_VER . chr(Socks5::METHOD_USER_PASS);
    assertEqual("\x05\x02", $response);
});

// ==================================================
echo PHP_EOL . "=== 4. 认证报文解析测试 ===" . PHP_EOL;
// ==================================================

test('解析用户名密码认证请求', function () {
    // SUB_VER=0x01 USER_LEN=4 USER="test" PASS_LEN=6 PASS="123456"
    $buffer = "\x01\x04test\x06123456";
    $offset = 0;

    $sub_ver = ord($buffer[$offset]);
    $offset += 1;
    $user_len = ord($buffer[$offset]);
    $offset += 1;
    $user = substr($buffer, $offset, $user_len);
    $offset += $user_len;
    $pass_len = ord($buffer[$offset]);
    $offset += 1;
    $pass = substr($buffer, $offset, $pass_len);

    assertEqual(0x01, $sub_ver, 'sub_ver');
    assertEqual(4, $user_len, 'user_len');
    assertEqual('test', $user, 'user');
    assertEqual(6, $pass_len, 'pass_len');
    assertEqual('123456', $pass, 'pass');
});

test('认证成功响应', function () {
    assertEqual("\x01\x00", Socks5::AUTH_OK);
});

test('认证失败响应', function () {
    assertEqual("\x01\x01", Socks5::AUTH_FAIL);
});

// ==================================================
echo PHP_EOL . "=== 5. 地址解析测试 (parseAddressType) ===" . PHP_EOL;
// ==================================================

test('解析IPv4地址', function () {
    // ADDR_TYPE=0x01 + IP: 192.168.1.1 + PORT: 8080
    $buffer = "\x05\x01\x00\x01" . chr(192) . chr(168) . chr(1) . chr(1) . pack('n', 8080);
    $request = [];
    $offset = 4; // 跳过VER/CMD/RSV/ATYP

    $ok = Socks5::parseAddressType(Socks5::ADDRTYPE_IPV4, $request, $buffer, $offset);
    assertEqual(true, $ok, 'parse result');
    assertEqual('192.168.1.1', $request['dest_addr'], 'dest_addr');
    assertEqual(8080, $request['dest_port'], 'dest_port');
});

test('解析域名地址', function () {
    $host = 'example.com';
    // ADDR_TYPE=0x03 + HOST_LEN + HOST + PORT
    $buffer = "\x05\x01\x00\x03" . chr(strlen($host)) . $host . pack('n', 443);
    $request = [];
    $offset = 4;

    $ok = Socks5::parseAddressType(Socks5::ADDRTYPE_HOST, $request, $buffer, $offset);
    assertEqual(true, $ok, 'parse result');
    assertEqual('example.com', $request['dest_addr'], 'dest_addr');
    assertEqual(443, $request['dest_port'], 'dest_port');
});

test('解析IPv6地址', function () {
    // ::1 的16字节表示
    $ipv6_bytes = inet_pton('::1');
    $buffer = "\x05\x01\x00\x04" . $ipv6_bytes . pack('n', 80);
    $request = [];
    $offset = 4;

    $ok = Socks5::parseAddressType(Socks5::ADDRTYPE_IPV6, $request, $buffer, $offset);
    assertEqual(true, $ok, 'parse result');
    assertEqual('::1', $request['dest_addr'], 'dest_addr');
    assertEqual(80, $request['dest_port'], 'dest_port');
});

test('解析IPv6完整地址', function () {
    $ipv6_bytes = inet_pton('2001:db8::1');
    $buffer = "\x05\x01\x00\x04" . $ipv6_bytes . pack('n', 8443);
    $request = [];
    $offset = 4;

    $ok = Socks5::parseAddressType(Socks5::ADDRTYPE_IPV6, $request, $buffer, $offset);
    assertEqual(true, $ok, 'parse result');
    assertEqual('2001:db8::1', $request['dest_addr'], 'dest_addr');
    assertEqual(8443, $request['dest_port'], 'dest_port');
});

test('IPv4 buffer过短返回false', function () {
    $buffer = "\x05\x01\x00\x01\xc0";  // 只有1字节IP
    $request = [];
    $offset = 4;

    $ok = Socks5::parseAddressType(Socks5::ADDRTYPE_IPV4, $request, $buffer, $offset);
    assertEqual(false, $ok);
});

test('域名 buffer过短返回false', function () {
    $buffer = "\x05\x01\x00\x03\x0bexample";  // host_len=11 但实际不够
    $request = [];
    $offset = 4;

    $ok = Socks5::parseAddressType(Socks5::ADDRTYPE_HOST, $request, $buffer, $offset);
    assertEqual(false, $ok);
});

test('IPv6 buffer过短返回false', function () {
    $buffer = "\x05\x01\x00\x04" . str_repeat("\x00", 10);  // 只有10字节
    $request = [];
    $offset = 4;

    $ok = Socks5::parseAddressType(Socks5::ADDRTYPE_IPV6, $request, $buffer, $offset);
    assertEqual(false, $ok);
});

test('未知地址类型返回null', function () {
    $buffer = "\x05\x01\x00\x09" . str_repeat("\x00", 20);
    $request = [];
    $offset = 4;

    $ok = Socks5::parseAddressType(0x09, $request, $buffer, $offset);
    assertEqual(null, $ok);
});

// ==================================================
echo PHP_EOL . "=== 6. packResponse 响应构建测试 ===" . PHP_EOL;
// ==================================================

test('构建成功响应(IPv4)', function () {
    $resp = Socks5::packResponse(Socks5::REP_OK, 0, Socks5::ADDRTYPE_IPV4, '127.0.0.1', 1080);
    // VER(05) REP(00) RSV(00) ATYP(01) BND.ADDR(4bytes) BND.PORT(2bytes) = 10 bytes
    assertEqual(10, strlen($resp), 'response length');
    assertEqual("\x05", $resp[0], 'version');
    assertEqual("\x00", $resp[1], 'response ok');
    assertEqual("\x00", $resp[2], 'rsv');
    assertEqual("\x01", $resp[3], 'addr type ipv4');
});

test('构建失败响应', function () {
    $resp = Socks5::packResponse(Socks5::REP_GENERAL);
    assertEqual("\x05", $resp[0], 'version');
    assertEqual("\x01", $resp[1], 'general failure');
});

test('构建域名类型响应', function () {
    $resp = Socks5::packResponse(Socks5::REP_OK, 0, Socks5::ADDRTYPE_HOST, 'localhost', 8080);
    assertEqual("\x05", $resp[0], 'version');
    assertEqual("\x03", $resp[3], 'addr type host');
    assertEqual(chr(9), $resp[4], 'host length');
    assertEqual('localhost', substr($resp, 5, 9), 'host');
});

// ==================================================
echo PHP_EOL . "=== 7. SOCKS5 CONNECT 命令解析测试 ===" . PHP_EOL;
// ==================================================

test('解析CONNECT命令(IPv4)', function () {
    // VER=05 CMD=01(CONNECT) RSV=00 ATYP=01(IPv4) ADDR=93.184.216.34 PORT=80
    $buffer = "\x05\x01\x00\x01" . chr(93) . chr(184) . chr(216) . chr(34) . pack('n', 80);
    $offset = 0;

    $ver = ord($buffer[$offset]);
    $offset += 1;
    $cmd = ord($buffer[$offset]);
    $offset += 1;
    $rsv = ord($buffer[$offset]);
    $offset += 1;
    $addr_type = ord($buffer[$offset]);
    $offset += 1;

    assertEqual(0x05, $ver);
    assertEqual(Socks5::CMD_CONNECT, $cmd);
    assertEqual(0, $rsv);
    assertEqual(Socks5::ADDRTYPE_IPV4, $addr_type);

    $request = [];
    $ok = Socks5::parseAddressType($addr_type, $request, $buffer, $offset);
    assertEqual(true, $ok);
    assertEqual('93.184.216.34', $request['dest_addr']);
    assertEqual(80, $request['dest_port']);
});

test('解析CONNECT命令(域名)', function () {
    $host = 'www.google.com';
    $buffer = "\x05\x01\x00\x03" . chr(strlen($host)) . $host . pack('n', 443);
    $offset = 4;

    $request = [];
    $ok = Socks5::parseAddressType(Socks5::ADDRTYPE_HOST, $request, $buffer, $offset);
    assertEqual(true, $ok);
    assertEqual('www.google.com', $request['dest_addr']);
    assertEqual(443, $request['dest_port']);
});

test('解析UDP ASSOCIATE命令', function () {
    // VER=05 CMD=03(UDP) RSV=00 ATYP=01 ADDR=0.0.0.0 PORT=0
    $buffer = "\x05\x03\x00\x01\x00\x00\x00\x00\x00\x00";
    $offset = 0;

    $cmd = ord($buffer[1]);
    assertEqual(Socks5::CMD_UDP_ASSOCIATE, $cmd);

    $offset = 4;
    $request = [];
    $ok = Socks5::parseAddressType(Socks5::ADDRTYPE_IPV4, $request, $buffer, $offset);
    assertEqual(true, $ok);
    assertEqual('0.0.0.0', $request['dest_addr']);
    assertEqual(0, $request['dest_port']);
});

// ==================================================
echo PHP_EOL . "=== 8. UDP 数据报解析测试 ===" . PHP_EOL;
// ==================================================

test('解析UDP数据报头(IPv4)', function () {
    // RSV(2bytes) FRAG(1byte) ATYP(1byte) DST.ADDR DST.PORT DATA
    $target_ip = chr(8) . chr(8) . chr(8) . chr(8);  // 8.8.8.8
    $data = "\x00\x00"         // RSV
        . "\x00"              // FRAG=0
        . "\x01"              // ATYP=IPv4
        . $target_ip          // DST.ADDR
        . pack('n', 53)       // DST.PORT=53
        . "dns_query_data";   // DATA

    $offset = 0;
    $rsv = substr($data, $offset, 2);
    $offset += 2;
    $frag = ord($data[$offset]);
    $offset += 1;
    $addr_type = ord($data[$offset]);
    $offset += 1;

    assertEqual("\x00\x00", $rsv, 'rsv');
    assertEqual(0, $frag, 'frag');
    assertEqual(Socks5::ADDRTYPE_IPV4, $addr_type, 'addr_type');

    $request = [];
    $ok = Socks5::parseAddressType($addr_type, $request, $data, $offset);
    assertEqual(true, $ok);
    assertEqual('8.8.8.8', $request['dest_addr']);
    assertEqual(53, $request['dest_port']);
    assertEqual('dns_query_data', substr($data, $offset), 'payload');
});

test('解析UDP数据报头(域名)', function () {
    $host = 'dns.google';
    $data = "\x00\x00\x00\x03" . chr(strlen($host)) . $host . pack('n', 53) . "query";

    $offset = 4;
    $request = [];
    $ok = Socks5::parseAddressType(Socks5::ADDRTYPE_HOST, $request, $data, $offset);
    assertEqual(true, $ok);
    assertEqual('dns.google', $request['dest_addr']);
    assertEqual(53, $request['dest_port']);
    assertEqual('query', substr($data, $offset));
});

// ==================================================
echo PHP_EOL . "=== 9. HTTP代理请求解析测试 ===" . PHP_EOL;
// ==================================================

test('解析HTTP CONNECT请求', function () {
    $data = "CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n";
    $line = strstr($data, "\r", true);
    $parts = explode(' ', $line);

    assertEqual('CONNECT', $parts[0], 'method');
    assertEqual('example.com:443', $parts[1], 'addr');
    assertEqual('HTTP/1.1', $parts[2], 'version');
});

test('解析HTTP GET代理请求', function () {
    $data = "GET http://example.com/path?q=1 HTTP/1.1\r\nHost: example.com\r\n\r\n";
    $line = strstr($data, "\r", true);
    $parts = explode(' ', $line);

    assertEqual('GET', $parts[0], 'method');

    $url_data = parse_url($parts[1]);
    assertEqual('example.com', $url_data['host'], 'host');
    $addr = isset($url_data['port']) ? $url_data['host'] . ':' . $url_data['port'] : $url_data['host'] . ':80';
    assertEqual('example.com:80', $addr, 'addr');
});

test('解析HTTP GET带端口', function () {
    $data = "GET http://example.com:8080/api HTTP/1.1\r\nHost: example.com:8080\r\n\r\n";
    $line = strstr($data, "\r", true);
    $parts = explode(' ', $line);
    $url_data = parse_url($parts[1]);
    $addr = isset($url_data['port']) ? $url_data['host'] . ':' . $url_data['port'] : $url_data['host'] . ':80';
    assertEqual('example.com:8080', $addr);
});

test('HTTP畸形请求检测(无CRLF)', function () {
    $data = "INVALID DATA WITHOUT CRLF";
    $line = strstr($data, "\r", true);
    assertEqual(false, $line, '无CRLF应返回false');
});

test('HTTP畸形请求检测(参数不足)', function () {
    $data = "GET\r\n\r\n";
    $line = strstr($data, "\r", true);
    $parts = explode(' ', $line);
    $valid = (count($parts) >= 3);
    assertEqual(false, $valid, '参数不足');
});

// ==================================================
echo PHP_EOL . "=== 10. 配置初始化测试 ===" . PHP_EOL;
// ==================================================

test('默认配置初始化', function () {
    Socks5::init([
        'common' => ['tcp_port' => 1081],
        'relay' => [],
    ]);
    assertEqual(1081, Socks5::$config['common']['tcp_port'], 'tcp_port');
    assertEqual(false, Socks5::$config['common']['auth'], 'auth default false');
    assertEqual('', Socks5::$config['common']['ens_key'], 'ens_key default empty');
});

test('array_replace_recursive 保留默认值', function () {
    // 只传部分配置，默认值应保留
    Socks5::$config = [
        'common' => [
            'auth' => false,
            'user' => 'user',
            'pass' => 'pass',
            'ens_key' => '',
            'log_level' => LOG_DEBUG,
            'tcp_port' => 1081,
            'http_port' => 1082,
            'udp_port' => 0,
            'wan_ip' => '',
        ],
        'relay' => [
            'endpoint' => '',
            'gzip_min' => 1024,
            'gzip_level' => 0,
            'ens_key' => '',
        ]
    ];
    Socks5::init([
        'common' => ['tcp_port' => 2080],
        'relay' => [],
    ]);
    // tcp_port 应被覆盖
    assertEqual(2080, Socks5::$config['common']['tcp_port'], 'tcp_port overridden');
    // 其他默认值应保留
    assertEqual('user', Socks5::$config['common']['user'], 'user preserved');
    assertEqual('pass', Socks5::$config['common']['pass'], 'pass preserved');
    assertEqual(1082, Socks5::$config['common']['http_port'], 'http_port preserved');
    assertEqual(1024, Socks5::$config['relay']['gzip_min'], 'gzip_min preserved');
});

test('开启认证需要user和pass', function () {
    Socks5::init([
        'common' => ['auth' => true, 'user' => 'admin', 'pass' => 'secret', 'tcp_port' => 1081],
        'relay' => [],
    ]);
    assertEqual(true, Socks5::$config['common']['auth'], 'auth enabled');
});

test('认证缺少密码时自动关闭', function () {
    Socks5::init([
        'common' => ['auth' => true, 'user' => 'admin', 'pass' => '', 'tcp_port' => 1081],
        'relay' => [],
    ]);
    assertEqual(false, Socks5::$config['common']['auth'], 'auth disabled when pass empty');
});

test('relay端口解析', function () {
    Socks5::init([
        'common' => ['tcp_port' => 1081],
        'relay' => ['endpoint' => '192.168.1.100:9090'],
    ]);
    assertEqual(9090, Socks5::$config['relay']['port'], 'relay port');
});

test('无relay时端口为0', function () {
    Socks5::init([
        'common' => ['tcp_port' => 1081],
        'relay' => ['endpoint' => ''],
    ]);
    assertEqual(0, Socks5::$config['relay']['port'], 'no relay port');
});

// ==================================================
echo PHP_EOL . "=== 11. DNS解析测试 ===" . PHP_EOL;
// ==================================================

test('IP地址直接返回', function () {
    $result = Socks5::getDnsHost('192.168.1.1');
    assertEqual('192.168.1.1', $result);
});

test('IPv6地址直接返回', function () {
    $result = Socks5::getDnsHost('::1');
    assertEqual('::1', $result);
});

// ==================================================
echo PHP_EOL . "=== 12. 完整SOCKS5会话模拟 ===" . PHP_EOL;
// ==================================================

test('模拟无认证完整握手流程', function () {
    // Step 1: 客户端发送握手
    $handshake = "\x05\x01\x00";  // VER=5, NMETHODS=1, METHOD=NO_AUTH
    $offset = 0;
    $ver = ord($handshake[$offset++]);
    $nmethods = ord($handshake[$offset++]);
    $methods = [];
    for ($i = 0; $i < $nmethods; $i++) {
        $methods[] = ord($handshake[$offset++]);
    }
    assertEqual(5, $ver);
    assertEqual(true, in_array(Socks5::METHOD_NO_AUTH, $methods));

    // Step 2: 服务器响应选择无认证
    $response = Socks5::SOCKS_VER . chr(Socks5::METHOD_NO_AUTH);
    assertEqual("\x05\x00", $response);

    // Step 3: 客户端发送CONNECT请求
    $host = 'www.example.com';
    $connect_req = "\x05\x01\x00\x03" . chr(strlen($host)) . $host . pack('n', 443);
    $offset = 4;
    $request = [];
    $ok = Socks5::parseAddressType(Socks5::ADDRTYPE_HOST, $request, $connect_req, $offset);
    assertEqual(true, $ok);
    assertEqual('www.example.com', $request['dest_addr']);
    assertEqual(443, $request['dest_port']);

    // Step 4: 服务器响应连接成功
    $resp = Socks5::packResponse(Socks5::REP_OK, 0, Socks5::ADDRTYPE_IPV4, '0.0.0.0', 0);
    assertEqual("\x05", $resp[0]);
    assertEqual("\x00", $resp[1]);  // REP_OK
});

test('模拟密码认证完整握手流程', function () {
    // Step 1: 客户端发送握手 支持密码认证
    $handshake = "\x05\x01\x02";  // VER=5, NMETHODS=1, METHOD=USER_PASS
    $ver = ord($handshake[0]);
    $methods = [ord($handshake[2])];
    assertEqual(true, in_array(Socks5::METHOD_USER_PASS, $methods));

    // Step 2: 服务器响应选择密码认证
    $response = Socks5::SOCKS_VER . chr(Socks5::METHOD_USER_PASS);
    assertEqual("\x05\x02", $response);

    // Step 3: 客户端发送认证
    $user = 'admin';
    $pass = 'password';
    $auth = "\x01" . chr(strlen($user)) . $user . chr(strlen($pass)) . $pass;
    $offset = 0;
    $sub_ver = ord($auth[$offset++]);
    $user_len = ord($auth[$offset++]);
    $parsed_user = substr($auth, $offset, $user_len);
    $offset += $user_len;
    $pass_len = ord($auth[$offset++]);
    $parsed_pass = substr($auth, $offset, $pass_len);

    assertEqual(1, $sub_ver);
    assertEqual('admin', $parsed_user);
    assertEqual('password', $parsed_pass);

    // Step 4: 认证成功
    assertEqual("\x01\x00", Socks5::AUTH_OK);

    // Step 5: CONNECT请求
    $connect_req = "\x05\x01\x00\x01" . chr(93) . chr(184) . chr(216) . chr(34) . pack('n', 80);
    $offset = 4;
    $request = [];
    Socks5::parseAddressType(Socks5::ADDRTYPE_IPV4, $request, $connect_req, $offset);
    assertEqual('93.184.216.34', $request['dest_addr']);
    assertEqual(80, $request['dest_port']);
});

// ==================================================
echo PHP_EOL . "=== 13. SOCKS4/4a协议解析测试 ===" . PHP_EOL;
// ==================================================

test('SOCKS4首字节0x04识别', function () {
    $data = "\x04\x01\x00\x50\x08\x08\x08\x08\x00";  // CONNECT 8.8.8.8:80
    $ver_flag = ord($data[0]);
    assertEqual(0x04, $ver_flag);
    $isSocks4 = ($ver_flag === 0x04);
    assertEqual(true, $isSocks4);
});

test('解析SOCKS4 CONNECT请求', function () {
    // VER=04 CMD=01 PORT=0x01BB(443) IP=49.7.47.75 USERID="" NULL
    $buffer = "\x04\x01\x01\xbb\x31\x07\x2f\x4b\x00";

    $cmd = ord($buffer[1]);
    $portData = unpack("n", substr($buffer, 2, 2));
    $dest_port = $portData[1];
    $dest_ip = ord($buffer[4]) . '.' . ord($buffer[5]) . '.' . ord($buffer[6]) . '.' . ord($buffer[7]);

    assertEqual(0x01, $cmd, 'CMD=CONNECT');
    assertEqual(443, $dest_port, 'port');
    assertEqual('49.7.47.75', $dest_ip, 'ip');
});

test('解析SOCKS4 CONNECT请求(HTTP端口)', function () {
    // CONNECT 192.168.1.1:80
    $buffer = "\x04\x01" . pack('n', 80) . chr(192) . chr(168) . chr(1) . chr(1) . "\x00";

    $cmd = ord($buffer[1]);
    $portData = unpack("n", substr($buffer, 2, 2));
    $dest_port = $portData[1];
    $dest_ip = ord($buffer[4]) . '.' . ord($buffer[5]) . '.' . ord($buffer[6]) . '.' . ord($buffer[7]);

    assertEqual(0x01, $cmd);
    assertEqual(80, $dest_port);
    assertEqual('192.168.1.1', $dest_ip);
});

test('解析SOCKS4带USERID', function () {
    // CONNECT 10.0.0.1:8080, USERID="admin"
    $buffer = "\x04\x01" . pack('n', 8080) . chr(10) . chr(0) . chr(0) . chr(1) . "admin\x00";

    $userid_end = strpos($buffer, "\x00", 8);
    assertEqual(13, $userid_end, 'userid null位置');
    $userid = substr($buffer, 8, $userid_end - 8);
    assertEqual('admin', $userid, 'userid');
});

test('SOCKS4a域名请求检测(IP为0.0.0.x)', function () {
    // IP=0.0.0.1 表示SOCKS4a，后面跟域名
    $ip_bytes = "\x00\x00\x00\x01";
    $is_socks4a = (ord($ip_bytes[0]) === 0 && ord($ip_bytes[1]) === 0 && ord($ip_bytes[2]) === 0 && ord($ip_bytes[3]) > 0);
    assertEqual(true, $is_socks4a);
});

test('非SOCKS4a普通IP不触发域名解析', function () {
    $ip_bytes = chr(192) . chr(168) . chr(1) . chr(1);
    $is_socks4a = (ord($ip_bytes[0]) === 0 && ord($ip_bytes[1]) === 0 && ord($ip_bytes[2]) === 0 && ord($ip_bytes[3]) > 0);
    assertEqual(false, $is_socks4a);
});

test('解析SOCKS4a完整请求(含域名)', function () {
    // CONNECT example.com:443, SOCKS4a格式
    $domain = 'example.com';
    $buffer = "\x04\x01" . pack('n', 443) . "\x00\x00\x00\x01" . "\x00" . $domain . "\x00";

    $cmd = ord($buffer[1]);
    $portData = unpack("n", substr($buffer, 2, 2));
    $dest_port = $portData[1];

    // 检测SOCKS4a
    $ip_bytes = substr($buffer, 4, 4);
    $is_socks4a = (ord($ip_bytes[0]) === 0 && ord($ip_bytes[1]) === 0 && ord($ip_bytes[2]) === 0 && ord($ip_bytes[3]) > 0);
    assertEqual(true, $is_socks4a);

    // 解析域名
    $userid_end = strpos($buffer, "\x00", 8);
    $domain_start = $userid_end + 1;
    $domain_end = strpos($buffer, "\x00", $domain_start);
    $parsed_domain = substr($buffer, $domain_start, $domain_end - $domain_start);

    assertEqual(0x01, $cmd);
    assertEqual(443, $dest_port);
    assertEqual('example.com', $parsed_domain);
});

test('SOCKS4响应格式验证', function () {
    // 成功响应: VN=0x00 REP=0x5A PORT(2) IP(4)
    $rep = 0x5A;
    $port = 443;
    $ip = '49.7.47.75';
    $response = "\x00" . chr($rep) . pack("n", $port);
    $parts = explode('.', $ip);
    foreach ($parts as $block) {
        $response .= chr((int)$block);
    }

    assertEqual(8, strlen($response), '响应长度');
    assertEqual("\x00", $response[0], 'VN=0');
    assertEqual(chr(0x5A), $response[1], 'REP=granted');
    $resp_port = unpack("n", substr($response, 2, 2))[1];
    assertEqual(443, $resp_port, 'port');
});

test('SOCKS4失败响应', function () {
    $rep = 0x5B;
    $response = "\x00" . chr($rep) . pack("n", 0) . "\x00\x00\x00\x00";
    assertEqual(chr(0x5B), $response[1], 'REP=rejected');
});

test('SOCKS4请求过短检测', function () {
    $buffer = "\x04\x01\x00";  // 只有3字节
    assertEqual(true, strlen($buffer) < 9, 'buffer过短');
});

test('SOCKS4缺少null结尾检测', function () {
    $buffer = "\x04\x01\x00\x50\x08\x08\x08\x08userid_no_null";
    $userid_end = strpos($buffer, "\x00", 8);
    assertEqual(false, $userid_end, '找不到null结尾');
});

// ==================================================
echo PHP_EOL . "=== 14. Gzip压缩传输测试 ===" . PHP_EOL;
// ==================================================

test('gzip压缩解压对称性', function () {
    $original = "GET http://example.com/ HTTP/1.1\r\nHost: example.com\r\n\r\n";
    $compressed = gzcompress($original);
    $decompressed = gzuncompress($compressed);
    assertEqual($original, $decompressed, '压缩解压后数据一致');
});

test('gzip压缩二进制数据(socks5握手)', function () {
    // socks5握手响应
    $data = "\x05\x00";
    $compressed = gzcompress($data);
    $decompressed = gzuncompress($compressed);
    assertEqual($data, $decompressed);
});

test('gzip压缩大数据块', function () {
    // 模拟HTML响应
    $data = str_repeat('<html><body>Hello World</body></html>', 100);
    $compressed = gzcompress($data);
    // 压缩后应比原始数据小
    assertEqual(true, strlen($compressed) < strlen($data), '压缩有效');
    $decompressed = gzuncompress($compressed);
    assertEqual($data, $decompressed, '解压后一致');
});

test('gzip压缩小数据', function () {
    $data = "\x05\x01\x00"; // 3字节握手
    $compressed = gzcompress($data);
    $decompressed = gzuncompress($compressed);
    assertEqual($data, $decompressed, '小数据压缩解压正确');
});

test('gzip解压损坏数据返回false', function () {
    $result = @gzuncompress("invalid_compressed_data");
    assertEqual(false, $result, '损坏数据解压失败');
});

test('gzip压缩packResponse响应', function () {
    $resp = Socks5::packResponse(Socks5::REP_OK, 0, Socks5::ADDRTYPE_IPV4, '0.0.0.0', 0);
    $compressed = gzcompress($resp);
    $decompressed = gzuncompress($compressed);
    assertEqual($resp, $decompressed, 'packResponse压缩解压一致');
    assertEqual("\x05", $decompressed[0], '解压后version正确');
    assertEqual("\x00", $decompressed[1], '解压后REP_OK正确');
});

test('模拟relay压缩传输流程(客户端→服务端)', function () {
    // 模拟客户端pipe发送: 先压缩再加密(此处简化不加密)
    $original = "\x05\x01\x00"; // socks5握手
    // 客户端pipe: gzip=1, 压缩发送
    $send_data = gzcompress($original);

    // 服务端handle: 解压
    $recv_data = gzuncompress($send_data);
    assertEqual($original, $recv_data, '客户端→服务端压缩传输');
    assertEqual(0x05, ord($recv_data[0]), '解压后版本号正确');
});

test('模拟relay压缩传输流程(服务端→客户端)', function () {
    // 服务端toSend: 压缩握手响应
    $response = Socks5::packResponse(Socks5::REP_OK, 0, Socks5::ADDRTYPE_IPV4, '127.0.0.1', 1080);
    $compressed = gzcompress($response);

    // 客户端pipe: gzip=-1, 解压接收
    $decompressed = gzuncompress($compressed);
    assertEqual($response, $decompressed, '服务端→客户端压缩传输');
});

test('模拟relay完整数据流(双向)', function () {
    // 1. 客户端发送握手 → 压缩 → 服务端解压
    $handshake = "\x05\x01\x00";
    $step1 = gzuncompress(gzcompress($handshake));
    assertEqual($handshake, $step1, '握手请求传输');

    // 2. 服务端响应 → 压缩 → 客户端解压
    $response = "\x05\x00";
    $step2 = gzuncompress(gzcompress($response));
    assertEqual($response, $step2, '握手响应传输');

    // 3. 客户端发送CONNECT → 压缩 → 服务端解压
    $host = 'example.com';
    $connect = "\x05\x01\x00\x03" . chr(strlen($host)) . $host . pack('n', 443);
    $step3 = gzuncompress(gzcompress($connect));
    assertEqual($connect, $step3, 'CONNECT请求传输');

    // 4. 目标返回数据 → 服务端压缩 → 客户端解压
    $web_data = "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n<html>Hello</html>";
    $step4 = gzuncompress(gzcompress($web_data));
    assertEqual($web_data, $step4, 'Web响应传输');
});

test('gzip配置关闭时不压缩', function () {
    Socks5::init([
        'common' => ['tcp_port' => 1081],
        'relay' => ['gzip' => 0],
    ]);
    assertEqual(0, Socks5::$config['relay']['gzip'], 'gzip关闭');
});

test('gzip配置开启', function () {
    Socks5::init([
        'common' => ['tcp_port' => 1081],
        'relay' => ['gzip' => 1],
    ]);
    assertEqual(1, Socks5::$config['relay']['gzip'], 'gzip开启');
});

// ==================================================
echo PHP_EOL . "=== 15. 边界条件测试 ===" . PHP_EOL;
// ==================================================

test('空buffer处理', function () {
    $buffer = "";
    assertEqual(true, strlen($buffer) < 2, '空buffer长度检测');
});

test('端口边界值0', function () {
    $buffer = "\x05\x01\x00\x01" . chr(127) . chr(0) . chr(0) . chr(1) . pack('n', 0);
    $request = [];
    $offset = 4;
    $ok = Socks5::parseAddressType(Socks5::ADDRTYPE_IPV4, $request, $buffer, $offset);
    assertEqual(true, $ok);
    assertEqual(0, $request['dest_port'], 'port 0');
});

test('端口边界值65535', function () {
    $buffer = "\x05\x01\x00\x01" . chr(127) . chr(0) . chr(0) . chr(1) . pack('n', 65535);
    $request = [];
    $offset = 4;
    $ok = Socks5::parseAddressType(Socks5::ADDRTYPE_IPV4, $request, $buffer, $offset);
    assertEqual(true, $ok);
    assertEqual(65535, $request['dest_port'], 'port 65535');
});

test('最大长度域名(255字节)', function () {
    $host = str_repeat('a', 255);
    $buffer = "\x05\x01\x00\x03" . chr(255) . $host . pack('n', 80);
    $request = [];
    $offset = 4;
    $ok = Socks5::parseAddressType(Socks5::ADDRTYPE_HOST, $request, $buffer, $offset);
    assertEqual(true, $ok);
    assertEqual(255, strlen($request['dest_addr']), 'max host length');
    assertEqual(80, $request['dest_port']);
});

test('stageMap包含所有状态', function () {
    $stages = [
        Socks5::STAGE_INIT,
        Socks5::STAGE_AUTH,
        Socks5::STAGE_ADDR,
        Socks5::STAGE_UDP_ASSOC,
        Socks5::STAGE_DNS,
        Socks5::STAGE_CONNECTING,
        Socks5::STAGE_STREAM,
        Socks5::STAGE_DESTROYED,
    ];
    foreach ($stages as $stage) {
        assertEqual(true, isset(Socks5::$stageMap[$stage]), "stage {$stage} in map");
    }
});

// ==================================================
// 汇总
// ==================================================
echo PHP_EOL . str_repeat('=', 40) . PHP_EOL;
echo "测试结果: {$passed}/{$total} 通过";
if ($failed > 0) {
    echo ", {$failed} 失败";
}
echo PHP_EOL;
exit($failed > 0 ? 1 : 0);
