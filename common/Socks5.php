<?php

namespace common;

use \Workerman\Connection\AsyncTcpConnection;
use \Workerman\Connection\AsyncUdpConnection;
use \Workerman\Connection\TcpConnection;
use Workerman\Connection\UdpConnection;
use Workerman\Worker;

class Socks5
{
    const SOCKS_VER = "\x05";
    const INIT_ERR = "\x05\xff";
    const AUTH_OK = "\x01\x00";
    const AUTH_FAIL = "\x01\x01";

    /**-------全局常量----------**/
    const STAGE_INIT = 0;
    const STAGE_AUTH = 1;
    const STAGE_ADDR = 2;
    const STAGE_UDP_ASSOC = 3;
    const STAGE_DNS = 4;
    const STAGE_CONNECTING = 5;
    const STAGE_STREAM = 6;
    const STAGE_DESTROYED = -1;

    /**
     * COMMAND 命令
     */
    const CMD_CONNECT = 0x01;  //CONNECT 连接目标服务器
    /**
     * BIND 绑定，客户端会接收来自代理服务器的链接，也就是说告诉代理服务器创建socket，监听来自目标机器的连接。像FTP服务器这种主动连接客户端的应用场景
     */
    const CMD_BIND = 0x02;
    const CMD_UDP_ASSOCIATE = 0x03; //UDP ASSOCIATE UDP中继

    /**
     * RESPONSE 响应命令
     */
    const REP_OK = 0; //代理服务器连接目标服务器成功
    const REP_GENERAL = 1; //代理服务器故障
    const REP_NOT_ALLOW = 2; //代理服务器规则集不允许连接
    const REP_NETWORK = 3; //网络无法访问
    const REP_HOST = 4; //目标服务器无法访问（主机名无效）
    const REP_REFUSE = 5; //连接目标服务器被拒绝
    const REP_TTL_EXPIRED = 6; //TTL已过期
    const REP_UNKNOW_COMMAND = 7; //不支持的命令
    const REP_UNKNOW_ADDR_TYPE = 8; //不支持的目标服务器地址类型
    const REP_UNKNOW = 9; //0xFF 未分配

    //ADDRESS_TYPE  目标服务器地址类型
    const ADDRTYPE_IPV4 = 0x01;  //IP V4地址
    const ADDRTYPE_HOST = 0x03; //域名地址 域名地址的第1个字节为域名长度，剩下字节为域名名称字节数组
    const ADDRTYPE_IPV6 = 0x04;

    /**
     * METHOD定义
     *
     * 0x00 不需要认证（常用）
     * 0x01 GSSAPI认证
     * 0x02 账号密码认证（常用）
     * 0x03 - 0x7F IANA分配
     * 0x80 - 0xFE 私有方法保留
     * 0xFF 无支持的认证方法
     */
    const METHOD_NO_AUTH = 0x00;
    const METHOD_GSSAPI = 0x01;
    const METHOD_USER_PASS = 0x02;

    public static $methodMap = [
        self::METHOD_NO_AUTH => 'NoAuth',
        self::METHOD_GSSAPI => 'GssApi',
        self::METHOD_USER_PASS => 'UserPass'
    ];

    public static $stageMap = [
        self::STAGE_INIT => 'INT',
        self::STAGE_AUTH => 'AUTH',
        self::STAGE_ADDR => 'ADDR',
        self::STAGE_UDP_ASSOC => 'UDP_ASSOC',
        self::STAGE_DNS => 'DNS',
        self::STAGE_CONNECTING => 'CONNECTING',
        self::STAGE_STREAM => 'STREAM',
        self::STAGE_DESTROYED => 'DESTROYED'
    ];

    //配置
    public static $config = [
        'common' => [
            "auth" => false,//METHOD_USER_PASS:1, METHOD_NO_AUTH:0
            'user' => 'user',
            'pass' => 'pass',
            'ens_key' => '', //数据加密key  rc4
            "log_level" => LOG_DEBUG,
            "tcp_port" => 1081,
            "http_port" => 1082, //http_port不指定时使用tcp_port+1
            "udp_port" => 0, //设置为0 表示由系统动态分配
            "wan_ip" => '', //对外IP用于udp服务
        ],
        'relay' => [ //中继
            'endpoint' => '', // http[s]://xxx, ws://xxx, tcp://xxx
            'gzip_min' => 1024, //1k
            'gzip_level' => 0, // 0-9 0不压缩 建议5
            'ens_key' => '', // 加密key
        ]
    ];

    public static function init(array $config)
    {
        if ($config) {
            self::$config = array_merge(self::$config, $config);
            if (!empty(self::$config['common']['auth']) && !empty($config['common']['user']) && !empty($config['common']['pass'])) {
                self::$config['common']['auth'] = true;
            } else {
                self::$config['common']['auth'] = false;
            }
        }
        //远端端口
        self::$config['relay']['port'] = 0;
        if (!empty($config['relay']['endpoint'])) {
            self::$config['relay']['port'] = (int)substr(strrchr(self::$config['relay']['endpoint'], ':'), 1);
        }
        if (empty($config['common']['ens_key'])) $config['common']['ens_key'] = '';
        if (empty($config['relay']['ens_key'])) $config['relay']['ens_key'] = '';
    }

    //目标服务器地址类型 ipv4
    public static function getDnsHost(string $dest_addr)
    {
        if (!filter_var($dest_addr, FILTER_VALIDATE_IP)) {
            logger(LOG_DEBUG, 'resolve DNS ' . $dest_addr);
            $addr = dns_get_record($dest_addr, DNS_A);
            $ip = null;
            if ($addr) {
                $addr = array_pop($addr);
                $ip = $addr['ip'];
            }
            logger(LOG_DEBUG, 'DNS resolved ' . $dest_addr . ' => ' . $ip);
        } else {
            $ip = $dest_addr;
        }
        return $ip;
    }

    /**
     * 代理服务器响应
     * VERSION:1    RESPONSE:1    RSV:1    ADDRESS_TYPE:    BND.ADDR:1-255    BND.PORT:2
     * @param int $response
     * @param int $rsv
     * @param int $address_type
     * @param string $bndAddr
     * @param int $bndPort
     * @return string
     */
    public static function packResponse(int $response = self::REP_OK, int $rsv = 0, int $address_type = self::ADDRTYPE_IPV4, string $bndAddr = '0.0.0.0', int $bndPort = 0)
    {
        $data = "";
        $data .= self::SOCKS_VER; //VERSION SOCKS协议版本，固定0x05
        $data .= chr($response);
        $data .= chr($rsv); //RSV 保留字段
        $data .= chr($address_type);

        switch ($address_type) {
            case self::ADDRTYPE_IPV4:
                $tmp = explode('.', $bndAddr);
                foreach ($tmp as $block) {
                    $data .= chr($block);
                }
                break;
            case self::ADDRTYPE_HOST:
                $host_len = strlen($bndAddr);
                $data .= chr($host_len);
                $data .= $bndAddr;
                break;
        }

        $data .= pack("n", $bndPort);
        logger(LOG_DEBUG, 'send:' . bin2hex($data));
        return $data;
    }

    /**
     * 解析地址及端口
     * @param int $addr_type
     * @param array $request
     * @param string $buffer
     * @param int $offset
     * @return bool|null
     */
    public static function parseAddressType(int $addr_type, array &$request, string &$buffer, int &$offset)
    {
        //DestAddr
        switch ($addr_type) {
            case self::ADDRTYPE_IPV4:
                if (strlen($buffer) < 4 + 4) {
                    logger(LOG_ERR, "connect init failed.[ADDRTYPE_IPV4] buffer too short.");
                    return false;
                }

                $tmp = substr($buffer, $offset, 4);
                $ip = 0;
                for ($i = 0; $i < 4; $i++) {
                    // var_dump(ord($tmp[$i]));
                    $ip += ord($tmp[$i]) * pow(256, 3 - $i);
                }
                $request['dest_addr'] = long2ip($ip);;
                $offset += 4;
                break;
            case self::ADDRTYPE_HOST:
                $request['host_len'] = ord($buffer[$offset]);
                $offset += 1;

                if (strlen($buffer) < 4 + 1 + $request['host_len']) {
                    logger(LOG_ERR, "connect init failed.[ADDRTYPE_HOST] buffer too short.");
                    return false;
                }

                $request['dest_addr'] = substr($buffer, $offset, $request['host_len']);
                $offset += $request['host_len'];
                break;

            case self::ADDRTYPE_IPV6:
                if (strlen($buffer) < 4 + 16) {  //22?
                    logger(LOG_ERR, "connect init failed.[ADDRTYPE_IPV6] buffer too short.");
                    return false;
                }
                $request['dest_addr'] = substr($buffer, $offset, 16);
                $offset += 16;
                break;
            default:
                logger(LOG_ERR, "unsupport ADDRTYPE." . $addr_type);
                return null;
        }

        // DestPort
        if (strlen($buffer) < $offset + 2) {
            logger(LOG_ERR, "connect init failed.[port] buffer too short.");
            return false;
        }
        $portData = unpack("n", substr($buffer, $offset, 2));
        $request['dest_port'] = $portData[1];
        $offset += 2;
        return true;
    }

    public static function connect(TcpConnection $conn, bool $socks=false)
    {
        //有代理中继
        if (!empty(self::$config['relay']['endpoint'])) {
            $conn->pauseRecv(); //暂停接收 待连接建立后恢复
            logger(LOG_DEBUG, 'relay connection init:'.$conn->id);
            // 建立中继的异步连接
            $relay = new AsyncTcpConnection('tcp://' . self::$config['relay']['endpoint']);
            if (self::$config['relay']['ens_key']) {
                $relay->protocol = '\\Workerman\\Protocols\\Frame'; //指定为定长包协议
            }
            $relay->onConnect = function (TcpConnection $relay) use ($conn) {
                logger(LOG_DEBUG, 'relay connection ok:'.$conn->id);

                $conn->resumeRecv(); //连接建立 恢复接收
            };

            self::pipe($conn, $relay, self::$config['common']['ens_key'], self::$config['relay']['ens_key']);
            self::pipe($relay, $conn, self::$config['relay']['ens_key'], self::$config['common']['ens_key']);

            $relay->onError = function (TcpConnection $relay, $err_code, $err_msg) use ($conn) {
                logger(LOG_DEBUG, "relay connect fail:".$conn->id.', ' . $err_code . ", " . $err_msg);
                $conn->close();
            };
            // 执行异步连接
            $relay->connect();
            return;
        }
        $conn->hasRecvData = false;
        if ($socks) {
            $conn->stage = self::STAGE_INIT;
            $conn->auth_type = null;
        }
    }

    public static function handle(TcpConnection $conn, string &$data)
    {
        //解密数据
        if (self::$config['common']['ens_key']) {
            logger(LOG_DEBUG, '<- 解密前:' . bin2hex(substr($data, 0, 20)));
            $data = deKey($data, self::$config['common']['ens_key']);
            logger(LOG_DEBUG, '<- 解密后:' . bin2hex(substr($data, 0, 20)));
        }
        logger(LOG_DEBUG, "recv<- " . $conn->getRemoteAddress() . ' <-> ' . $conn->getLocalAddress() . ":" . bin2hex(substr($data, 0, 40)));
        //第一次收到数据时判断请求类型 http|socks5
        if (!$conn->hasRecvData) {
            $conn->hasRecvData = true;

            if (substr($data, 0, 4) === 'CONN') {
                // http
            } else {
                //socks
                $conn->stage = self::STAGE_INIT;
                $conn->auth_type = NULL;
            }
        }

        if (isset($conn->stage)) {
            self::proxySocks($conn, $data, false);
        } else {
            self::proxyHttp($conn, $data, false);
        }
    }

    public static function proxySocks(\Workerman\Connection\TcpConnection $conn, string &$buffer, $decrypt=true)
    {
        //解密数据
        if ($decrypt && self::$config['common']['ens_key']) {
            logger(LOG_DEBUG, '<-socks ' . Socks5::$stageMap[$conn->stage] . ' 解密前:' . bin2hex(substr($buffer, 0, 20)));
            $buffer = deKey($buffer, self::$config['common']['ens_key']);
            logger(LOG_DEBUG, '<-socks ' . Socks5::$stageMap[$conn->stage] . ' 解密后:' . bin2hex(substr($buffer, 0, 20)));
        }
        logger(LOG_DEBUG, "[" . Socks5::$stageMap[$conn->stage] . "]recv<- " . $conn->getRemoteAddress() . ' <-> ' . $conn->getLocalAddress() . ":" . bin2hex(substr($buffer, 0, 40)));
        switch ($conn->stage) {
            // 初始化环节  握手请求
            case self::STAGE_INIT:
                $request = [];
                // 当前偏移量
                $offset = 0;
                // 检测buffer长度
                if (strlen($buffer) < 2) {
                    logger(LOG_ERR, "init failed. buffer too short.");
                    return Socks5::failClose($conn, self::INIT_ERR);
                }
                // 握手请求  VER:1 NMETHODS:1 METHODS:1-255
                /**
                 * VER 字段表征 Socks 协议版本, 占 1 字节, 对于 Socks 5 其值固定为 0x05
                 * NMETHODS 字段指示其后的 METHOD 字段所占的字节数, 其本身占 1 字节
                 * METHODS 字段为可变长字段, 用来指示客户端和代理服务器之间的认证方法, 其长度区间为 [1, 255] 个字节
                 *
                 * 0xFF 无支持的认证方法
                 */
                // Socks5 版本
                $request['ver'] = ord($buffer[$offset]);
                $offset += 1;
                // 认证方法数量
                $request['method_count'] = ord($buffer[$offset]);
                $offset += 1;
                if (strlen($buffer) < 2 + $request['method_count']) {
                    logger(LOG_ERR, "init authentic failed. buffer too short.");
                    return Socks5::failClose($conn, self::INIT_ERR);
                }

                // 客户端支持的认证方法
                $request['methods'] = [];
                for ($i = 1; $i <= $request['method_count']; $i++) {
                    $request['methods'][] = ord($buffer[$offset]);
                    $offset++;
                }
                //向客户端发回握手响应 VER:1 METHOD:1
                /**
                 *  VER 字段与客户端请求数据包的 VER 字段含义相同, 表征协议版本, 固定为 0x05
                 *
                 * METHOD定义
                 * 0x00 不需要认证（常用）
                 * 0x01 GSSAPI认证
                 * 0x02 账号密码认证（常用）
                 * 0x03 - 0x7F IANA分配
                 * 0x80 - 0xFE 私有方法保留
                 * 0xFF 无支持的认证方法
                 */
                //仅支持 无验证和账号密码验证  不支持GSSAPI
                $k = self::$config['common']['auth'] ? self::METHOD_USER_PASS : self::METHOD_NO_AUTH;
                if (in_array($k, $request['methods'])) {
                    logger(LOG_INFO, "auth client " . Socks5::$methodMap[$k]);
                    logger(LOG_DEBUG, "send:" . bin2hex(self::SOCKS_VER . chr($k)));

                    Socks5::toSend($conn, self::SOCKS_VER . chr($k));
                    if ($k == 0) {
                        $conn->stage = self::STAGE_ADDR;
                    } else {
                        $conn->stage = self::STAGE_AUTH;
                    }
                    $conn->auth_type = $k; //记录客户端的认证方式
                    break;
                }
                if ($conn->stage != self::STAGE_AUTH) {
                    logger(LOG_ERR, "client has no matched auth methods");
                    logger(LOG_DEBUG, "send:" . bin2hex(self::INIT_ERR) . json_encode($request['methods']));
                    //当代理服务器对于客户端所声明的所有认证方法都不支持, 此时代理服务器将 METHOD 字段值为 0xFF
                    return Socks5::failClose($conn, self::INIT_ERR);
                }
                break;
            // 认证环节  VERSION:1	USERNAME_LENGTH:1	USERNAME:1-255	PASSWORD_LENGTH:1	PASSWORD:1-255
            case self::STAGE_AUTH:
                $request = [];
                // 当前偏移量
                $offset = 0;

                if (strlen($buffer) < 5) {
                    logger(LOG_ERR, "auth failed. buffer too short.");
                    return Socks5::failClose($conn, self::AUTH_FAIL);
                }

                // var_dump($conn->auth_type);
                switch ($conn->auth_type) {
                    case self::METHOD_USER_PASS:
                        //  子协议 协商 版本
                        $request['sub_ver'] = ord($buffer[$offset]);
                        $offset += 1;
                        // 用户名
                        $request['user_len'] = ord($buffer[$offset]);
                        $offset += 1;

                        if (strlen($buffer) < 2 + $request['user_len'] + 2) {
                            logger(LOG_ERR, "auth username failed. buffer too short.");
                            return Socks5::failClose($conn, self::AUTH_FAIL);
                        }

                        $request['user'] = substr($buffer, $offset, $request['user_len']);
                        $offset += $request['user_len'];

                        // 密码
                        $request['pass_len'] = ord($buffer[$offset]);
                        $offset += 1;

                        //var_dump($request);

                        if (strlen($buffer) < 2 + $request['user_len'] + 1 + $request['pass_len']) {
                            logger(LOG_ERR, "auth password failed. buffer too short.");
                            return Socks5::failClose($conn, self::AUTH_FAIL);
                        }

                        $request['pass'] = substr($buffer, $offset, $request['pass_len']);
                        $offset += $request['pass_len'];

                        //服务器响应账号密码认证结果 VERSION:1 STATUS:1
                        /**
                         * VERSION 认证子协商版本，与客户端VERSION字段一致
                         * STATUS 认证结果（0x00 认证成功大于0x00 认证失败）
                         */
                        if (self::$config['common']["user"] == $request['user'] && self::$config['common']["pass"] == $request['pass']) {
                            logger(LOG_INFO, "auth ok");
                            Socks5::toSend($conn, self::AUTH_OK); //\x01\x00
                            $conn->stage = STAGE_ADDR;
                        } else {
                            logger(LOG_INFO, "auth failed");
                            return Socks5::failClose($conn, self::AUTH_FAIL);
                        }
                        break;
                    default:
                        logger(LOG_ERR, "unsupport auth type");
                        return Socks5::failClose($conn, self::AUTH_FAIL);
                }
                break;
            //命令过程 VERSION:1	COMMAND:1	RSV:1	ADDRESS_TYPE:1	DST.ADDR:1-255	DST.PORT:2
            /**
             * VERSION SOCKS协议版本，固定0x05
             * COMMAND 命令
             * RSV 保留字段
             * ADDRESS_TYPE 目标服务器地址类型
             * DST.ADDR ip地址
             * DST.PORT 端口号
             *
             * 说明：这里的DST.ADDR和DST.PORT在COMMAND不同时有不用的表示
             * CONNECT 希望连接的target服务器ip地址和端口号
             * BIND 希望连接的target服务器ip地址和端口号
             * UDP ASSOCIATE 客户端本地使用的ip地址和端口号，代理服务器可以用这个信息对访问进行一些限制。
             */
            case self::STAGE_ADDR:
                $request = [];
                // 当前偏移量
                $offset = 0;

                if (strlen($buffer) < 4) {
                    logger(LOG_ERR, "connect init failed. buffer too short.");
                    return Socks5::failClose($conn, Socks5::packResponse(self::REP_GENERAL));
                }

                // Socks 版本
                $request['ver'] = ord($buffer[$offset]);
                $offset += 1;

                // 命令
                $request['command'] = ord($buffer[$offset]);
                $offset += 1;

                // RSV
                $request['rsv'] = ord($buffer[$offset]);
                $offset += 1;

                // AddressType
                $request['addr_type'] = ord($buffer[$offset]);
                $offset += 1;

                // DestAddr  DestPort
                $ok = Socks5::parseAddressType($request['addr_type'], $request, $buffer, $offset);
                if (!$ok) {
                    logger(LOG_DEBUG, 'addr_fail: ' . toJson($request));
                    return Socks5::failClose($conn, Socks5::packResponse($ok === null ? self::REP_UNKNOW_ADDR_TYPE : self::REP_GENERAL));
                }

                // var_dump($request);
                switch ($request['command']) {
                    case self::CMD_CONNECT:
                        logger(LOG_DEBUG, 'tcp://' . $request['dest_addr'] . ':' . $request['dest_port']);

                        $dest_addr = $request['dest_addr'];
                        if ($request['addr_type'] == self::ADDRTYPE_HOST) {
                            $request['dest_addr'] = Socks5::getDnsHost($request['dest_addr']);
                        }
                        if ($request['dest_addr']) { //代理
                            $conn->stage = self::STAGE_CONNECTING;
                            $remote = new AsyncTcpConnection('tcp://' . $request['dest_addr'] . ':' . $request['dest_port']);
                            logger(LOG_DEBUG, 'tcp://' . $request['dest_addr'] . ':' . $request['dest_port'] . ' [初始连接]');

                            $remote->onConnect = function (\Workerman\Connection\TcpConnection $remote) use ($conn, $request) {
                                $conn->state = self::STAGE_STREAM;
                                //连接成功，回复的数据包中的 BND.ADDR，BND.PORT 没有太大的意义，象征性的填写Socks 服务端在此次连接中使用的 ADDR 和 PORT 即可。
                                $bind_addr = '0.0.0.0'; //$remote->getLocalIp(); //'0.0.0.0'
                                $bind_port = 12345; //$remote->getLocalPort(); //12345
                                Socks5::toSend($conn, Socks5::packResponse(self::REP_OK, 0, $request['addr_type'], $bind_addr, $bind_port));
                                logger(LOG_DEBUG, 'tcp://' . $request['dest_addr'] . ':' . $request['dest_port'] . ' [连接OK]');
                            };

                            self::pipe($conn, $remote, self::$config['common']['ens_key']);
                            self::pipe($remote, $conn, '', self::$config['common']['ens_key']);
                            $remote->connect();
                        } else {
                            logger(LOG_NOTICE, 'DNS resolve failed. ' . $dest_addr);
                            return Socks5::failClose($conn, Socks5::packResponse(self::REP_HOST));
                        }
                        break;
                    case self::CMD_UDP_ASSOCIATE:
                        $conn->stage = self::STAGE_UDP_ASSOC;
                        if (self::$config['common']['udp_port'] == 0) {

                            $conn->udpWorker = new \Workerman\Worker('udp://0.0.0.0:0'); //系统自动分配端口
                            $conn->udpWorker->incId = 0;
                            $conn->udpWorker->onMessage = function ($udp_connection, $data) use ($conn) {
                                Socks5::udpWorkerOnMessage($udp_connection, $data, $conn->udpWorker);
                            };
                            $conn->udpWorker->listen();
                            $listenInfo = stream_socket_get_name($conn->udpWorker->getMainSocket(), false);
                            list($bind_addr, $bind_port) = explode(":", $listenInfo);
                            var_dump($listenInfo);
                            $bind_port = self::$config['common']['tcp_port'];
                        } else {
                            $bind_port = self::$config['common']['udp_port'];
                        }
                        //todo 测试udp
                        $listenInfo = stream_socket_get_name($conn->worker->getMainSocket(), false);
                        if (empty(self::$config['common']['wan_ip'])) { //未匹配时 直接使用本地ip 可能不支持公网穿透
                            $bind_addr = $conn->getLocalIp();
                        } else {
                            $bind_addr = self::$config['common']['wan_ip'];  //对外ip
                        }

                        logger(LOG_DEBUG, "CMD_UDP_ASSOCIATE " . self::$config['common']['udp_port'] . ', main:' . $listenInfo . ', local:' . $conn->getLocalAddress() . ', remote:' . $conn->getRemoteAddress() . ', bind:' . $bind_addr . ':' . $bind_port);
                        Socks5::toSend($conn, Socks5::packResponse(self::REP_OK, 0, self::ADDRTYPE_IPV4, $bind_addr, $bind_port));
                        break;
                    case self::CMD_BIND:
                        logger(LOG_ERR, "connect init failed. todo CMD_BIND.");
                        return Socks5::failClose($conn, Socks5::packResponse(self::REP_UNKNOW_COMMAND));
                    default:
                        logger(LOG_ERR, "connect init failed. unknow command.");
                        return Socks5::failClose($conn, Socks5::packResponse(self::REP_UNKNOW_COMMAND));
                }
        }
    }

    public static function proxyHttp(TcpConnection $conn, string &$data, $decrypt=true){
        //解密数据
        if ($decrypt && self::$config['common']['ens_key']) {
            logger(LOG_DEBUG, '<-http 解密前:' . bin2hex(substr($data, 0, 20)));
            $data = deKey($data, self::$config['common']['ens_key']);
            logger(LOG_DEBUG, '<-http 解密后:' . bin2hex(substr($data, 0, 20)));
        }
        // Parse http header.
        $line = strstr($data, "\r", true);
        list($method, $addr, $http_version) = explode(' ', $line);
        logger(LOG_DEBUG, 'http recv:'.$line);
        $url_data = parse_url($addr);
        $addr = isset($url_data['port']) ? $url_data['host'] . ':' . $url_data['port'] : $url_data['host'] . ':80';
        // Async TCP connection.
        $remote = new \Workerman\Connection\AsyncTcpConnection("tcp://$addr");
        // CONNECT.
        if ($method !== 'CONNECT') {
            $remote->send($data);
            // POST GET PUT DELETE etc.
        } else {
            self::toSend($conn, $http_version." 200 Connection Established\r\n\r\n");
            //$conn->send($http_version." 200 Connection Established\r\n\r\n");
        }

        self::pipe($conn, $remote, self::$config['common']['ens_key']);
        self::pipe($remote, $conn, '', self::$config['common']['ens_key']);

        $remote->connect();
    }

    public static function pipe(TcpConnection $conn, TcpConnection $dest, $ens_key='', $relay_key=''){
        $conn->onMessage = function ($conn, $data) use ($dest, $ens_key, $relay_key) {
            //本端有设置密码 解密
            if ($ens_key !== '') {
                logger(LOG_DEBUG, '<-pipe 解密前:' . $conn->getLocalAddress() . ' - ' . $conn->getRemoteAddress());
                logger(LOG_DEBUG, '<-pipe 解密前:' . bin2hex(substr($data, 0, 20)));
                $data = deKey($data, $ens_key);
                logger(LOG_DEBUG, '<-pipe 解密后:' . bin2hex(substr($data, 0, 20)));
            } else {
                logger(LOG_DEBUG, '<-pipe 无解密:' . $conn->getLocalAddress() . ' - ' . $conn->getRemoteAddress());
                logger(LOG_DEBUG, '<-pipe 无解密:' . bin2hex(substr($data, 0, 20)));
            }
            //远端有设置密码 加密
            if ($relay_key !== '') {
                logger(LOG_DEBUG, '->pipe 加密前:' . $dest->getLocalAddress() . ' - ' . $dest->getRemoteAddress());
                logger(LOG_DEBUG, '->pipe 加密前:' . bin2hex(substr($data, 0, 20)));
                $data = enKey($data, $relay_key);
                logger(LOG_DEBUG, '->pipe 加密后:' . bin2hex(substr($data, 0, 20)));
            } else {
                logger(LOG_DEBUG, '->pipe 无加密:' . $dest->getLocalAddress() . ' - ' . $dest->getRemoteAddress());
                logger(LOG_DEBUG, '->pipe 无加密:' . bin2hex(substr($data, 0, 20)));
            }

            $dest->send($data);
        };
        $conn->onClose = function ($conn) use ($dest) {
            $dest->close();
        };
        $dest->onBufferFull = function ($dest) use ($conn) {
            $conn->pauseRecv();
        };
        $dest->onBufferDrain = function ($dest) use ($conn) {
            $conn->resumeRecv();
        };
    }

    public static function failClose(TcpConnection $conn, string $msg, int $stage = self::STAGE_DESTROYED)
    {
        self::toSend($conn, $msg);
        logger(LOG_DEBUG, 'close id[' . $conn->id . ']');
        $conn->stage = $stage;
        $conn->close();
        return true;
    }

    public static function toSend(\Workerman\Connection\TcpConnection $conn, string $buffer)
    {
        $type = isset($conn->stage) ? 'socks' : 'http';
        if (self::$config['common']['ens_key']) {
            logger(LOG_DEBUG, '->'.$type.' pipe 加密前:' . bin2hex(substr($buffer, 0, 20)));
            $buffer = enKey($buffer, self::$config['common']['ens_key']);
            logger(LOG_DEBUG, '->'.$type.' pipe 加密后:' . bin2hex(substr($buffer, 0, 20)));
        }
        logger(LOG_DEBUG, '->'.$type.': ' . $conn->getRemoteAddress() . ' <-> ' . $conn->getLocalAddress() . ", send:" . bin2hex(substr($buffer, 0, 20)));
        return $conn->send($buffer);
    }

    /**
     * 数据转发
     * 如果代理的是tcp连接则直接转发tcp数据。如果代理的是udp数据客户端和代理服务器之间需要对原始UDP数据包进行包装之后再进行转发。
     *
     * RSV:2    FRAG:1    ATYP:1    DST.ADDR:1-255    DST.PORT:2    DATA:variable...
     * RSV 保留字段
     * FRAG 包编号
     * ATYP 目标服务器地址类型
     * 0x01 IP V4地址
     * 0x03 域名地址(没有打错，就是没有0x02)，域名地址的第1个字节为域名长度，剩下字节为域名名称字节数组
     * 0x04 IP V6地址
     * DST.ADDR 目标服务器地址
     * DST.PORT 目标服务器端口
     * DATA 用户数据
     * @param \Workerman\Connection\UdpConnection $udp_connection
     * @param string $data
     * @param \Workerman\Worker $worker
     * @return mixed
     * @throws \Exception
     */
    public static function udpWorkerOnMessage(UdpConnection $udp_connection, string $data, Worker &$worker = null)
    {
        //todo test
        logger(LOG_DEBUG, '[udp]' . $udp_connection->getLocalAddress() . ' - ' . $udp_connection->getRemoteAddress() . ' send:' . bin2hex($data));
        $request = [];
        $offset = 0;

        $request['rsv'] = substr($data, $offset, 2);
        $offset += 2;

        $request['frag'] = ord($data[$offset]);
        $offset += 1;

        $request['addr_type'] = ord($data[$offset]);
        $offset += 1;

        // DestAddr  DestPort
        $ok = Socks5::parseAddressType($request['addr_type'], $request, $data, $offset);
        if (!$ok) {
            logger(LOG_DEBUG, '[udp]DNS resolve failed.');
            return $udp_connection->close();
        }

        // var_dump($request['dest_addr']);
        // var_dump($request);
        if ($request['addr_type'] == self::ADDRTYPE_HOST) {
            $request['dest_addr'] = Socks5::getDnsHost($request['dest_addr']);
        }
        if (!$request['dest_addr']) {
            logger(LOG_DEBUG, '[udp]send:' . bin2hex($data));
            return $udp_connection->close();
        }
        $remote = new AsyncUdpConnection('udp://' . $request['dest_addr'] . ':' . $request['dest_port']);
        $remote->id = $worker->incId++;
        $remote->udp_connection = $udp_connection;
        $remote->onConnect = function ($remote) use ($data, $offset) {
            $remote->send(substr($data, $offset));
        };
        $remote->onMessage = function ($remote, $recv) use ($data, $offset, $udp_connection, $worker) {
            $udp_connection->close(substr($data, 0, $offset) . $recv);
            $remote->close();
            unset($worker->udpConnections[$remote->id]);
        };
        $remote->deadTime = time() + 3;
        $remote->connect();
        $worker->udpConnections[$remote->id] = $remote;
    }
}