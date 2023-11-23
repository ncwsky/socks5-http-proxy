#!/usr/bin/env php
<?php
error_reporting(E_ALL);
ini_set('display_errors', 'On');// 有些环境关闭了错误显示

if (!defined('RUN_DIR') && realpath(dirname($_SERVER['SCRIPT_FILENAME'])) != __DIR__) {
    define('RUN_DIR', realpath(dirname($_SERVER['SCRIPT_FILENAME'])));
}
defined('RUN_DIR') || define('RUN_DIR', __DIR__);

if (!defined('VENDOR_DIR')) {
    if (is_dir(__DIR__ . '/vendor')) {
        define('VENDOR_DIR', __DIR__ . '/vendor');
    } elseif (is_dir(__DIR__ . '/../vendor')) {
        define('VENDOR_DIR', __DIR__ . '/../vendor');
    } elseif (is_dir(__DIR__ . '/../../../vendor')) {
        define('VENDOR_DIR', __DIR__ . '/../../../vendor');
    }
}

defined('STOP_TIMEOUT') || define('STOP_TIMEOUT', 10); //进程结束超时时间 秒
defined('MAX_INPUT_SIZE') || define('MAX_INPUT_SIZE', 2097152); //接收包限制大小1M 1048576

defined('MY_PHP_DIR') || define('MY_PHP_DIR', VENDOR_DIR . '/myphps/myphp');
require VENDOR_DIR . '/autoload.php';
require MY_PHP_DIR . '/GetOpt.php';

//解析命令参数
GetOpt::parse('hp:l:u:c:e:r:E:w:', ['help', 'port:', 'listen:','udp:','key:','relay:','relay_key:','wan_ip:']);

//解析配置文件
$config = GetOpt::val('c'); // config.ini|xx.php
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
    $ini = require(__DIR__ . '/config.php');
    //处理命令参数
    $tcp_port = (int)GetOpt::val('p', 'port');
    $udp_port = (int)GetOpt::val('u', 'udp');
    $ens_key = GetOpt::val('e', 'key');
    $relay = GetOpt::val('r', 'relay');
    $r_ens_key = GetOpt::val('E', 'relay_key');
    $wan_ip = GetOpt::val('w', 'wan_ip');

    if ($tcp_port) $ini['common']['tcp_port'] = $tcp_port;
    if ($udp_port) $ini['common']['udp_port'] = $udp_port;
    if ($ens_key) $ini['common']['ens_key'] = $ens_key;
    if ($wan_ip) $ini['common']['wan_ip'] = $wan_ip;
    if ($r_ens_key) $ini['relay']['ens_key'] = $r_ens_key;
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
   -c 配置文件     优先使用配置文件 
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
        'count' => 10, //单进程模式
        'stdoutFile' => RUN_DIR . '/log.log', //终端输出
        'pidFile' => RUN_DIR . '/socks'.$port.'.pid',  //pid_file
        'logFile' => RUN_DIR . '/log.log', //日志文件 log_file
    ],
    'event' => [
        'onWorkerStart' => function (Workerman\Worker $worker) use($ini) {
            \common\Socks5::init($ini);
        },
        'onConnect' => function (Workerman\Connection\TcpConnection $conn) {
            logger(LOG_DEBUG, 'tcp conn:' . $conn->id);
            \common\Socks5::connect($conn);
        },
        'onClose' => function (Workerman\Connection\TcpConnection $conn){
            \SrvBase::$isConsole && SrvBase::safeEcho(date("Y-m-d H:i:s.").substr(microtime(),2, 5).' onClose '.$conn->id.PHP_EOL);
        },
        'onMessage' => function (Workerman\Connection\TcpConnection $conn, $data) {
            \common\Socks5::handle($conn, $data);
        },
    ],
    'listen' => [
        'udp' => [
            'type'=>'udp',
            'ip' => $listen,
            'port' => $udp_port,
            'setting' => [
                'count' => 10,
            ],
            'event' => [
                'onWorkerStart' => function (Workerman\Worker $worker) use($ini) {
                    \common\Socks5::init($ini);
                    $worker->udpConnections = [];
                    \Workerman\Timer::add(1, function () use ($worker) {
                        foreach ($worker->udpConnections as $id => $remote_connection) {
                            if ($remote_connection->deadTime < time()) {
                                $remote_connection->close();
                                $remote_connection->udp_connection->close();
                                unset($worker->udpConnections[$id]);
                            }
                        }
                    });
                },
                'onConnect' => function (Workerman\Connection\TcpConnection $conn) {
                    logger(LOG_DEBUG, 'udp conn:'.$conn->id);
                },
                'onMessage' => function (Workerman\Connection\UdpConnection $connection, $data) {
                    \common\Socks5::udpWorkerOnMessage($connection, $data, SrvBase::$instance->server);
                },
            ]
        ],
    ],
    // 进程内加载的文件
    'worker_load' => [
        MY_PHP_DIR . '/base.php',
        function () {
            if (__DIR__ != RUN_DIR) {
                myphp::class_dir(__DIR__ . '/common');
            }
        }
    ],
];

//如果加密使用定长包
if ($ini['common']['ens_key']) {
    $conf['setting']['protocol'] = '\\Workerman\\Protocols\\Frame';
    $conf['listen']['udp']['setting']['protocol'] = '\\Workerman\\Protocols\\Frame';
}
// 设置每个连接接收的最大数据包
\Workerman\Connection\TcpConnection::$defaultMaxPackageSize = MAX_INPUT_SIZE;
$srv = new WorkerManSrv($conf);
Worker2::$stopTimeout = STOP_TIMEOUT; //强制进程结束等待时间
$srv->run($argv);

function logger($level, $str)
{
    global $ini;
    if ($ini['common']['debug'] || $level!=LOG_DEBUG) {
        SrvBase::safeEcho(date("Y-m-d H:i:s.") . substr(microtime(), 2, 5) . ' ' . $str . PHP_EOL);
    }
}

function enKey(&$data, $key){
    $data = \myphp\Helper::aesEncrypt($data, $key);
    #$data = xor_enc($data, $key);//"\x6a\x6d".$data; //test
    #$data = "\x6a\x6d".$data; //test
    return $data;
}
function deKey(&$data, $key){
    $data = \myphp\Helper::aesDecrypt($data, $key);
    #$data = xor_enc($data, $key);//substr($data,2); //test
    #$data = substr($data,2); //test
    return $data;
}