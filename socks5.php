#!/usr/bin/env php
<?php

error_reporting(E_ALL);
ini_set('display_errors', 'On');// 有些环境关闭了错误显示

$_SERVER['SCRIPT_FILENAME'] = __FILE__; //重置运行

require __DIR__ . '/vendor/autoload.php';
require __DIR__ . '/vendor/myphps/myphp/GetOpt.php';

defined('PROC_COUNT') || define('PROC_COUNT', 2); //进程数
//Phar包路径处理
if (class_exists(Phar::class, false) && Phar::running(false)) {
    define('MY_PHAR_PATH', Phar::running()); //Phar内部运行目录
    define('APP_RUN_DIR', dirname(Phar::running(false))); //Phar的运行目录
    $_SERVER['SCRIPT_FILENAME'] = Phar::running(false); //重置
    $inPhar = true;
} else {
    define('APP_RUN_DIR', __DIR__);
    $inPhar = false;
}

//解析命令参数
GetOpt::parse('hp:l:u:c:e:r:E:w:', ['help', 'port:', 'listen:','udp:','config:','key:','relay:','relay_key:','wan_ip:']);

//解析配置文件
$config = GetOpt::val('c', 'config', 'config.ini'); // config.ini|xx.php
if ($config && file_exists($config)) {
    if (strpos($config, '.php')) {
        $ini = require($config);
    } else {
        $ini = parse_ini_file($config, true);
    }

    if (!$ini || empty($ini['common']['tcp_port'])) {
        echo $config . ' invalid';
        exit(0);
    }
} else {
    $ini = require(file_exists(APP_RUN_DIR . '/config.php') ? APP_RUN_DIR . '/config.php' : __DIR__ . '/config.example.php');
    //处理命令参数
    $tcp_port = (int)GetOpt::val('p', 'port');
    $udp_port = (int)GetOpt::val('u', 'udp');
    $ens_key = GetOpt::val('e', 'key');
    $relay = GetOpt::val('r', 'relay');
    $r_ens_key = GetOpt::val('E', 'relay_key');
    $wan_ip = GetOpt::val('w', 'wan_ip');
    $listen_addr = GetOpt::val('l', 'listen');

    if ($tcp_port) {
        $ini['common']['tcp_port'] = $tcp_port;
    }
    if ($udp_port) {
        $ini['common']['udp_port'] = $udp_port;
    }
    if ($ens_key) {
        $ini['common']['ens_key'] = $ens_key;
    }
    if ($wan_ip) {
        $ini['common']['wan_ip'] = $wan_ip;
    }
    if ($r_ens_key) {
        $ini['relay']['ens_key'] = $r_ens_key;
    }
    if ($relay) {
        $ini['relay']['endpoint'] = $relay;
    }
    if ($listen_addr) {
        $ini['common']['listen'] = $listen_addr;
    }
}

if (empty($ini['common']['wan_ip'])) {
    $urls = ['https://api64.ipify.org', 'https://ifconfig.me/ip', 'https://ipinfo.io/ip'];
    foreach ($urls as $url) {
        $response = file_get_contents($url);
        if ($response) {
            break;
        } else {
            echo $url . ' fail' . PHP_EOL;
        }
    }
    if (!$response) {
        echo 'wan_ip get fail';
        exit(0);
    }
    //$externalIp = exec("curl -s ifconfig.me"); echo "External IP: " . $externalIp . "\n";
    $ini['common']['wan_ip'] = $response;
    echo "wan_ip: " . $response . "\n";
}

$listen = $ini['common']['listen'] ?? '0.0.0.0';
$port = $ini['common']['tcp_port'];
$udp_port = $ini['common']['udp_port'];
if ($udp_port == 0) {
    $ini['common']['udp_port'] = $udp_port = $port;
}
$http_port = $port + 1;

if (GetOpt::has('h', 'help')) {
    echo 'Usage: php socks5.php OPTION [restart|reload|stop]
   or: socks5.php OPTION [restart|reload|stop]

   --help
   -c --config    配置文件     优先使用配置文件
   -l --listen    监听地址(默认0.0.0.0)
   -p --port      tcp 端口
   -u --udp       udp 端口
   -e --key       加密key
   -r --relay     中继节点 ip:端口
   -E --relay_key 中继加密key
   -w --wan_ip    接入网络IP', PHP_EOL;
    exit(0);
}

$conf = [
    'name' => 'mySocks5',
    'ip' => $listen,
    'port' => $port,
    'type' => 'tcp',
    'setting' => [
        'count' => PROC_COUNT, //单进程模式
        'stdoutFile' => APP_RUN_DIR . '/log.log', //终端输出
        'pidFile' => APP_RUN_DIR . '/socks'.$port.'.pid',  //pid_file
        'logFile' => APP_RUN_DIR . '/log.log', //日志文件 log_file
    ],
    'event' => [
        'onWorkerStart' => function (Workerman\Worker $worker) use ($ini) {
            \common\Socks5::init($ini);
        },
        'onConnect' => function (Workerman\Connection\TcpConnection $conn) {
            logger(LOG_DEBUG, 'tcp conn:' . $conn->id);
            \common\Socks5::connect($conn);
        },
        'onClose' => function (Workerman\Connection\TcpConnection $conn) {
            // 清理动态创建的UDP Worker（UDP ASSOCIATE时创建）
            if (isset($conn->context->udpWorker)) {
                $conn->context->udpWorker->unlisten();
                $conn->context->udpWorker = null;
            }
            \SrvBase::$isConsole && SrvBase::safeEcho(date("Y-m-d H:i:s.").substr(microtime(), 2, 5).' onClose '.$conn->id.PHP_EOL);
        },
        'onMessage' => function (Workerman\Connection\TcpConnection $conn, $data) {
            \common\Socks5::handle($conn, $data);
        },
    ],
    'listen' => [
        'udp' => [
            'type' => 'udp',
            'ip' => $listen,
            'port' => $udp_port,
            'setting' => [
                'count' => PROC_COUNT,
            ],
            'event' => [
                'onWorkerStart' => function (Workerman\Worker $worker) use ($ini) {
                    \common\Socks5::init($ini, true);
                },
                'onConnect' => function (Workerman\Connection\TcpConnection $conn) {
                    logger(LOG_DEBUG, 'udp conn:'.$conn->id);
                },
                'onMessage' => function (Workerman\Connection\UdpConnection $connection, $data) {
                    \common\Socks5::udpWorkerOnMessage($connection, $data);
                },
            ]
        ],
    ],
    // 进程内加载的文件
    'worker_load' => [
        __DIR__ . '/vendor/myphps/myphp/base.php'
    ],
];

//如果加密使用定长包
if ($ini['common']['ens_key']) {
    $conf['setting']['protocol'] = '\\Workerman\\Protocols\\Frame';
    $conf['listen']['udp']['setting']['protocol'] = '\\Workerman\\Protocols\\Frame';
}
// 设置每个连接接收的最大数据包
\Workerman\Connection\TcpConnection::$defaultMaxPackageSize = 10 * 1024 * 1024;
$srv = new WorkerManSrv($conf);
Worker2::$stopTimeout = 10; //强制进程结束等待时间
$srv->run($argv);

function logger($level, $str)
{
    global $ini;
    if (!empty($ini['common']['debug']) || $level !== LOG_DEBUG) {
        SrvBase::safeEcho(date("Y-m-d H:i:s.") . substr(microtime(), 2, 5) . ' ' . $str . PHP_EOL);
    }
}

function enKey(&$data, $key)
{
    $data = \myphp\Helper::aesEncrypt($data, $key);
    #$data = xor_enc($data, $key);//"\x6a\x6d".$data; //test
    #$data = "\x6a\x6d".$data; //test
    return $data;
}
function deKey(&$data, $key)
{
    $data = \myphp\Helper::aesDecrypt($data, $key);
    #$data = xor_enc($data, $key);//substr($data,2); //test
    #$data = substr($data,2); //test
    return $data;
}
