<?php

namespace common;

use Workerman\Connection\AsyncTcpConnection;
use Workerman\Connection\AsyncUdpConnection;
use Workerman\Connection\TcpConnection;
use Workerman\Connection\UdpConnection;
use Workerman\Worker;

class Socks5
{
    public const SOCKS_VER = "\x05";
    public const INIT_ERR = "\x05\xff";
    public const AUTH_OK = "\x01\x00";
    public const AUTH_FAIL = "\x01\x01";

    /**-------全局常量----------**/
    public const STAGE_INIT = 0;
    public const STAGE_AUTH = 1;
    public const STAGE_ADDR = 2;
    public const STAGE_UDP_ASSOC = 3;
    public const STAGE_DNS = 4;
    public const STAGE_CONNECTING = 5;
    public const STAGE_STREAM = 6;
    public const STAGE_DESTROYED = -1;

    /**
     * COMMAND 命令
     */
    public const CMD_CONNECT = 0x01;  //CONNECT 连接目标服务器
    /**
     * BIND 绑定，客户端会接收来自代理服务器的链接，也就是说告诉代理服务器创建socket，监听来自目标机器的连接。像FTP服务器这种主动连接客户端的应用场景
     */
    public const CMD_BIND = 0x02;
    public const CMD_UDP_ASSOCIATE = 0x03; //UDP ASSOCIATE UDP中继

    /**
     * RESPONSE 响应命令
     */
    public const REP_OK = 0; //代理服务器连接目标服务器成功
    public const REP_GENERAL = 1; //代理服务器故障
    public const REP_NOT_ALLOW = 2; //代理服务器规则集不允许连接
    public const REP_NETWORK = 3; //网络无法访问
    public const REP_HOST = 4; //目标服务器无法访问（主机名无效）
    public const REP_REFUSE = 5; //连接目标服务器被拒绝
    public const REP_TTL_EXPIRED = 6; //TTL已过期
    public const REP_UNKNOW_COMMAND = 7; //不支持的命令
    public const REP_UNKNOW_ADDR_TYPE = 8; //不支持的目标服务器地址类型
    public const REP_UNKNOW = 9; //0xFF 未分配

    //ADDRESS_TYPE  目标服务器地址类型
    public const ADDRTYPE_IPV4 = 0x01;  //IP V4地址
    public const ADDRTYPE_HOST = 0x03; //域名地址 域名地址的第1个字节为域名长度，剩下字节为域名名称字节数组
    public const ADDRTYPE_IPV6 = 0x04;

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
    public const METHOD_NO_AUTH = 0x00;
    public const METHOD_GSSAPI = 0x01;
    public const METHOD_USER_PASS = 0x02;

    /**
     * @var array spl_object_id=>[conn, dead_time]
     */
    public static $udpConnections = [];

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
            "tcp_port" => 1081,
            "http_port" => 1082, //http_port不指定时使用tcp_port+1
            "udp_port" => 0, //设置为0 表示由系统动态分配
            "wan_ip" => '', //对外IP用于udp服务
        ],
        'relay' => [ //中继
            'endpoint' => '', // http[s]://xxx, ws://xxx, tcp://xxx
            'gzip' => 0, // 1启用gzip压缩传输
            'ens_key' => '', // 加密key
        ]
    ];

    public static function init(array $config, $udp = false)
    {
        if ($config) {
            self::$config = array_replace_recursive(self::$config, $config);
            if (!empty(self::$config['common']['auth']) && !empty(self::$config['common']['user']) && !empty(self::$config['common']['pass'])) {
                self::$config['common']['auth'] = true;
            } else {
                self::$config['common']['auth'] = false;
            }
        }
        //远端端口
        self::$config['relay']['port'] = 0;
        if (!empty(self::$config['relay']['endpoint'])) {
            self::$config['relay']['port'] = (int)substr(strrchr(self::$config['relay']['endpoint'], ':'), 1);
        }
        if (empty(self::$config['common']['ens_key'])) {
            self::$config['common']['ens_key'] = '';
        }
        if (empty(self::$config['relay']['ens_key'])) {
            self::$config['relay']['ens_key'] = '';
        }

        if ($udp) { //udp初始定时清理连接
            \Workerman\Timer::add(1, function () {
                foreach (self::$udpConnections as $id => $item) {
                    [$remote_connection, $deadTime, $udp_connection] = $item;
                    if ($deadTime < time()) {
                        $remote_connection->close();
                        $udp_connection->close();
                        unset(self::$udpConnections[$id]);
                    }
                }
            });
        }
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
        $data = '';
        $data .= self::SOCKS_VER; //VERSION SOCKS协议版本，固定0x05
        $data .= chr($response);
        $data .= chr($rsv); //RSV 保留字段
        $data .= chr($address_type);

        switch ($address_type) {
            case self::ADDRTYPE_IPV4:
                $tmp = explode('.', $bndAddr);
                foreach ($tmp as $block) {
                    $data .= chr((int)$block);
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
                if (strlen($buffer) < $offset + 4) { //4+4
                    logger(LOG_ERR, "connect init failed.[ADDRTYPE_IPV4] buffer too short.");
                    return false;
                }

                $tmp = substr($buffer, $offset, 4);
                $ip = 0;
                for ($i = 0; $i < 4; $i++) {
                    // var_dump(ord($tmp[$i]));
                    $ip += ord($tmp[$i]) * pow(256, 3 - $i);
                }
                $request['dest_addr'] = long2ip($ip);
                $offset += 4;
                break;
            case self::ADDRTYPE_HOST:
                $request['host_len'] = ord($buffer[$offset]);
                $offset += 1;

                if (strlen($buffer) < $offset + $request['host_len']) { // 4+1+$request['host_len']
                    logger(LOG_ERR, "connect init failed.[ADDRTYPE_HOST] buffer too short.");
                    return false;
                }

                $request['dest_addr'] = substr($buffer, $offset, $request['host_len']);
                $offset += $request['host_len'];
                break;

            case self::ADDRTYPE_IPV6:
                if (strlen($buffer) < $offset + 16) { // 4+16 22?
                    logger(LOG_ERR, "connect init failed.[ADDRTYPE_IPV6] buffer too short.");
                    return false;
                }
                $request['dest_addr'] = inet_ntop(substr($buffer, $offset, 16));
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

    public static function connect(TcpConnection $conn, bool $socks = false)
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

            $gzip = !empty(self::$config['relay']['gzip']) ? 1 : 0;
            // 客户端→relay: 压缩后发送(gzip=1)，relay→客户端: 接收后解压(gzip=-1)
            self::pipe($conn, $relay, self::$config['common']['ens_key'], self::$config['relay']['ens_key'], $gzip);
            self::pipe($relay, $conn, self::$config['relay']['ens_key'], self::$config['common']['ens_key'], $gzip ? -1 : 0);

            $relay->onError = function (TcpConnection $relay, $err_code, $err_msg) use ($conn) {
                logger(LOG_DEBUG, "relay connect fail:".$conn->id.', ' . $err_code . ", " . $err_msg);
                $conn->close();
            };
            // 执行异步连接
            $relay->connect();
            return;
        }
        $conn->context->hasRecvData = false;
        if ($socks) {
            $conn->context->stage = self::STAGE_INIT;
            $conn->context->auth_type = null;
        }
    }

    public static function handle(TcpConnection $conn, string &$data)
    {
        if ($data === '') {
            return;
        }
        //解密数据
        if (self::$config['common']['ens_key']) {
            logger(LOG_DEBUG, '<- 解密前:' . bin2hex(substr($data, 0, 20)));
            $data = deKey($data, self::$config['common']['ens_key']);
            logger(LOG_DEBUG, '<- 解密后:' . bin2hex(substr($data, 0, 20)));
        }
        // relay端接收解压（对端启用了gzip压缩时）
        if (!empty(self::$config['relay']['gzip']) && strlen($data) > 0) {
            $data = @gzuncompress($data);
            if ($data === false) {
                logger(LOG_ERR, 'handle gzip decompress failed');
                $conn->close();
                return;
            }
            logger(LOG_DEBUG, 'handle gzip decompress ok, size:' . strlen($data));
        }
        logger(LOG_DEBUG, "recv<- " . $conn->getRemoteAddress() . ' <-> ' . $conn->getLocalAddress() . ":" . bin2hex(substr($data, 0, 40)));
        //第一次收到数据时判断请求类型 http|socks5
        if (!$conn->context->hasRecvData) {
            $conn->context->hasRecvData = true;

            $ver_flag = ord($data[0]);
            if ($ver_flag === 0x05) {
                //socks5 协议版本号为0x05
                $conn->context->stage = self::STAGE_INIT;
                $conn->context->auth_type = null;
            } elseif ($ver_flag === 0x04) {
                //socks4 协议，直接处理并return
                self::proxySocks4($conn, $data);
                return;
            }
            // 否则视为http代理请求
        }

        if (isset($conn->context->stage)) {
            self::proxySocks($conn, $data, false);
        } else {
            self::proxyHttp($conn, $data, false);
        }
    }

    /**
     * SOCKS4/4a 协议处理
     * 请求格式: VER(1) CMD(1) DSTPORT(2) DSTIP(4) USERID(变长,null结尾) [DOMAIN(变长,null结尾,仅4a)]
     * 响应格式: VN(0x00) REP(1) DSTPORT(2) DSTIP(4)
     */
    public static function proxySocks4(TcpConnection $conn, string &$buffer)
    {
        if (strlen($buffer) < 9) {
            logger(LOG_ERR, "socks4 request too short: " . bin2hex($buffer));
            $conn->close();
            return;
        }

        $cmd = ord($buffer[1]);
        $portData = unpack("n", substr($buffer, 2, 2));
        $dest_port = $portData[1];
        $ip_bytes = substr($buffer, 4, 4);
        $dest_ip = ord($ip_bytes[0]) . '.' . ord($ip_bytes[1]) . '.' . ord($ip_bytes[2]) . '.' . ord($ip_bytes[3]);

        // 跳过 USERID（null结尾）
        $userid_end = strpos($buffer, "\x00", 8);
        if ($userid_end === false) {
            logger(LOG_ERR, "socks4 missing null terminator for userid");
            $conn->close();
            return;
        }

        // SOCKS4a: 当IP为 0.0.0.x (x>0) 时，USERID后面跟域名
        if (ord($ip_bytes[0]) === 0 && ord($ip_bytes[1]) === 0 && ord($ip_bytes[2]) === 0 && ord($ip_bytes[3]) > 0) {
            $domain_start = $userid_end + 1;
            $domain_end = strpos($buffer, "\x00", $domain_start);
            if ($domain_end === false) {
                logger(LOG_ERR, "socks4a missing null terminator for domain");
                $conn->close();
                return;
            }
            $dest_addr = substr($buffer, $domain_start, $domain_end - $domain_start);
            logger(LOG_INFO, "socks4a CONNECT {$dest_addr}:{$dest_port}");
            // DNS解析
            $dest_ip = self::getDnsHost($dest_addr);
            if (!$dest_ip) {
                logger(LOG_ERR, "socks4a DNS resolve failed: {$dest_addr}");
                self::socks4Response($conn, 0x5B);
                return;
            }
        } else {
            $dest_addr = $dest_ip;
            logger(LOG_INFO, "socks4 CONNECT {$dest_ip}:{$dest_port}");
        }

        if ($cmd !== 0x01) { // 仅支持 CONNECT
            logger(LOG_ERR, "socks4 unsupported cmd: 0x" . dechex($cmd));
            self::socks4Response($conn, 0x5B);
            return;
        }

        // 建立到目标的异步连接
        $remote = new AsyncTcpConnection("tcp://{$dest_ip}:{$dest_port}");

        $remote->onConnect = function (TcpConnection $remote) use ($conn, $dest_ip, $dest_port) {
            logger(LOG_DEBUG, "socks4 tcp://{$dest_ip}:{$dest_port} [连接OK]");
            self::socks4Response($conn, 0x5A, $dest_port, $dest_ip);
        };

        $remote->onError = function ($remote, $err_code, $err_msg) use ($conn, $dest_ip, $dest_port) {
            logger(LOG_ERR, "socks4 tcp://{$dest_ip}:{$dest_port} connect fail: {$err_code} {$err_msg}, from: " . $conn->getRemoteAddress());
            self::socks4Response($conn, 0x5B);
        };

        self::pipe($conn, $remote, self::$config['common']['ens_key']);
        self::pipe($remote, $conn, '', self::$config['common']['ens_key']);
        $remote->connect();
    }

    /**
     * SOCKS4 响应: VN(0x00) REP(1) DSTPORT(2) DSTIP(4)
     * REP: 0x5A=成功, 0x5B=失败
     */
    private static function socks4Response(TcpConnection $conn, int $rep, int $port = 0, string $ip = '0.0.0.0')
    {
        $response = "\x00" . chr($rep) . pack("n", $port);
        $parts = explode('.', $ip);
        foreach ($parts as $block) {
            $response .= chr((int)$block);
        }
        logger(LOG_DEBUG, "socks4 response: " . bin2hex($response));
        self::toSend($conn, $response);
        if ($rep !== 0x5A) {
            $conn->close();
        }
    }

    public static function proxySocks(\Workerman\Connection\TcpConnection $conn, string &$buffer, $decrypt = true)
    {
        //解密数据
        if ($decrypt && self::$config['common']['ens_key']) {
            logger(LOG_DEBUG, '<-socks ' . Socks5::$stageMap[$conn->context->stage] . ' 解密前:' . bin2hex(substr($buffer, 0, 20)));
            $buffer = deKey($buffer, self::$config['common']['ens_key']);
            logger(LOG_DEBUG, '<-socks ' . Socks5::$stageMap[$conn->context->stage] . ' 解密后:' . bin2hex(substr($buffer, 0, 20)));
        }
        logger(LOG_DEBUG, "[" . Socks5::$stageMap[$conn->context->stage] . "]recv<- " . $conn->getRemoteAddress() . ' <-> ' . $conn->getLocalAddress() . ":" . bin2hex(substr($buffer, 0, 40)));
        switch ($conn->context->stage) {
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
                    logger(LOG_DEBUG, "auth client " . Socks5::$methodMap[$k]);
                    logger(LOG_DEBUG, "send:" . bin2hex(self::SOCKS_VER . chr($k)));

                    Socks5::toSend($conn, self::SOCKS_VER . chr($k));
                    if ($k === self::METHOD_NO_AUTH) {
                        $conn->context->stage = self::STAGE_ADDR;
                    } else {
                        $conn->context->stage = self::STAGE_AUTH;
                    }
                    $conn->context->auth_type = $k; //记录客户端的认证方式
                    break;
                }
                if ($conn->context->stage !== self::STAGE_AUTH) {
                    logger(LOG_ERR, "client has no matched auth methods");
                    logger(LOG_ERR, "send:" . bin2hex(self::INIT_ERR) . ', stage:' . $conn->context->stage . json_encode($request['methods']));
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

                // var_dump($conn->context->auth_type);
                switch ($conn->context->auth_type) {
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
                            $conn->context->stage = self::STAGE_ADDR;
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
                            $conn->context->stage = self::STAGE_CONNECTING;
                            $remote = new AsyncTcpConnection('tcp://' . $request['dest_addr'] . ':' . $request['dest_port']);
                            logger(LOG_DEBUG, 'tcp://' . $request['dest_addr'] . ':' . $request['dest_port'] . ' [初始连接]');

                            $remote->onConnect = function (\Workerman\Connection\TcpConnection $remote) use ($conn, $request) {
                                $conn->context->stage = self::STAGE_STREAM;
                                //连接成功，回复的数据包中的 BND.ADDR，BND.PORT 没有太大的意义，象征性的填写Socks 服务端在此次连接中使用的 ADDR 和 PORT 即可。
                                $bind_addr = '0.0.0.0'; //$remote->getLocalIp(); //'0.0.0.0'
                                $bind_port = 12345; //$remote->getLocalPort(); //12345
                                Socks5::toSend($conn, Socks5::packResponse(self::REP_OK, 0, $request['addr_type'], $bind_addr, $bind_port));
                                logger(LOG_DEBUG, 'tcp://' . $request['dest_addr'] . ':' . $request['dest_port'] . ' [连接OK]');
                            };

                            $remote->onError = function ($remote, $err_code, $err_msg) use ($conn, $request) {
                                logger(LOG_ERR, 'tcp://' . $request['dest_addr'] . ':' . $request['dest_port'] . " socks5 connect fail: {$err_code} {$err_msg}, from: " . $conn->getRemoteAddress());
                                Socks5::failClose($conn, Socks5::packResponse(self::REP_NETWORK));
                            };

                            $gzip = !empty(self::$config['relay']['gzip']) ? 1 : 0;
                            // 客户端→目标: 解密+解压; 目标→客户端: 压缩+加密
                            self::pipe($conn, $remote, self::$config['common']['ens_key'], '', $gzip ? -1 : 0);
                            self::pipe($remote, $conn, '', self::$config['common']['ens_key'], $gzip);
                            $remote->connect();
                        } else {
                            logger(LOG_NOTICE, 'DNS resolve failed. ' . $dest_addr);
                            return Socks5::failClose($conn, Socks5::packResponse(self::REP_HOST));
                        }
                        break;
                    case self::CMD_UDP_ASSOCIATE:
                        $conn->context->stage = self::STAGE_UDP_ASSOC;
                        if (self::$config['common']['udp_port'] == 0) {
                            // 动态分配UDP端口
                            $conn->context->udpWorker = new \Workerman\Worker('udp://0.0.0.0:0');
                            $conn->context->udpWorker->onMessage = function ($udp_connection, $data) {
                                Socks5::udpWorkerOnMessage($udp_connection, $data);
                            };
                            $conn->context->udpWorker->listen();
                            $listenInfo = stream_socket_get_name($conn->context->udpWorker->getMainSocket(), false);
                            $bind_port = (int)substr(strrchr($listenInfo, ':'), 1);
                        } else {
                            // 使用全局UDP Worker端口
                            $bind_port = self::$config['common']['udp_port'];
                        }
                        // 确定对外绑定地址 未匹配时 直接使用本地ip 可能不支持公网穿透
                        $bind_addr = !empty(self::$config['common']['wan_ip'])
                            ? self::$config['common']['wan_ip']
                            : $conn->getLocalIp();

                        logger(LOG_DEBUG, "CMD_UDP_ASSOCIATE bind:{$bind_addr}:{$bind_port}, local:" . $conn->getLocalAddress() . ', remote:' . $conn->getRemoteAddress());
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

    public static function proxyHttp(TcpConnection $conn, string &$data, $decrypt = true)
    {
        //解密数据
        if ($decrypt && self::$config['common']['ens_key']) {
            logger(LOG_DEBUG, '<-http 解密前:' . bin2hex(substr($data, 0, 20)));
            $data = deKey($data, self::$config['common']['ens_key']);
            logger(LOG_DEBUG, '<-http 解密后:' . bin2hex(substr($data, 0, 20)));
        }
        // Parse http header.
        $line = strstr($data, "\r", true);
        if (!$line) {
            logger(LOG_ERR, 'http invalid request, no CRLF '. $data);
            $conn->close();
            return;
        }
        $parts = explode(' ', $line);
        if (count($parts) < 3) {
            logger(LOG_ERR, 'http invalid request line: ' . $line.' --- '.$data);
            $conn->close();
            return;
        }
        [$method, $addr, $http_version] = $parts;
        logger(LOG_DEBUG, 'http recv:'.$line);
        $url_data = parse_url($addr);
        if (empty($url_data['host'])) {
            logger(LOG_ERR, 'http invalid host: ' . $addr);
            $conn->close();
            return;
        }
        $addr = isset($url_data['port']) ? $url_data['host'] . ':' . $url_data['port'] : $url_data['host'] . ':80';
        // Async TCP connection.
        $remote = new \Workerman\Connection\AsyncTcpConnection("tcp://$addr");

        if ($method === 'CONNECT') {
            // CONNECT隧道：必须等远程连接建立后再回复200
            $remote->onConnect = function ($remote) use ($conn, $http_version) {
                self::toSend($conn, $http_version . " 200 Connection Established\r\n\r\n");
            };
        } else {
            // GET/POST等：直接转发原始请求
            $remote->send($data);
        }

        $remote->onError = function ($remote, $err_code, $err_msg) use ($conn, $method, $http_version) {
            logger(LOG_ERR, "http remote connect fail: {$err_code} {$err_msg}, from: " . $conn->getRemoteAddress());
            if ($method === 'CONNECT') {
                self::toSend($conn, $http_version . " 502 Bad Gateway\r\n\r\n");
            }
            $conn->close();
        };

        $gzip = !empty(self::$config['relay']['gzip']) ? 1 : 0;
        // 客户端→目标: 解密+解压; 目标→客户端: 压缩+加密
        self::pipe($conn, $remote, self::$config['common']['ens_key'], '', $gzip ? -1 : 0);
        self::pipe($remote, $conn, '', self::$config['common']['ens_key'], $gzip);

        $remote->connect();
    }

    /**
     * 数据管道转发
     * @param string $ens_key 本端解密key（接收时解密）
     * @param string $relay_key 远端加密key（发送时加密）
     * @param int $gzip 压缩方向: 0=不压缩, 1=发送时压缩, -1=接收时解压
     */
    public static function pipe(TcpConnection $conn, TcpConnection $dest, $ens_key = '', $relay_key = '', int $gzip = 0)
    {
        $conn->onMessage = function ($conn, $data) use ($dest, $ens_key, $relay_key, $gzip) {
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

            // 接收时解压（从relay端收到的数据）
            if ($gzip === -1 && strlen($data) > 0) {
                $data = @gzuncompress($data);
                if ($data === false) {
                    logger(LOG_ERR, 'pipe gzip decompress failed');
                    $conn->close();
                    return;
                }
                logger(LOG_DEBUG, 'gzip decompress ok, size:' . strlen($data));
            }

            // 发送时压缩（发往relay端的数据）
            if ($gzip === 1) {
                $compressed = gzcompress($data);
                logger(LOG_DEBUG, 'gzip compress ' . strlen($data) . ' -> ' . strlen($compressed));
                $data = $compressed;
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
        $conn->context->stage = $stage;
        $conn->close();
        return true;
    }

    public static function toSend(\Workerman\Connection\TcpConnection $conn, string $buffer)
    {
        $type = isset($conn->context->stage) ? 'socks' : 'http';
        // relay端响应压缩
        if (!empty(self::$config['relay']['gzip'])) {
            $buffer = gzcompress($buffer);
            logger(LOG_DEBUG, '->'.$type.' gzip compress, size:' . strlen($buffer));
        }
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
     * @return mixed
     * @throws \Exception
     */
    public static function udpWorkerOnMessage(UdpConnection $udp_connection, string $data)
    {
        logger(LOG_DEBUG, '[udp]' . $udp_connection->getLocalAddress() . ' - ' . $udp_connection->getRemoteAddress() . ' recv:' . bin2hex(substr($data, 0, 40)));

        // 最小长度校验: RSV(2) + FRAG(1) + ATYP(1) = 4字节 + 至少地址和端口
        if (strlen($data) < 10) {
            logger(LOG_ERR, '[udp] packet too short: ' . strlen($data));
            return;
        }

        $request = [];
        $offset = 0;

        $request['rsv'] = substr($data, $offset, 2);
        $offset += 2;

        $request['frag'] = ord($data[$offset]);
        $offset += 1;

        // 分片包暂不支持重组，丢弃非首片
        if ($request['frag'] !== 0) {
            logger(LOG_DEBUG, '[udp] fragmented packet dropped, frag=' . $request['frag']);
            return;
        }

        $request['addr_type'] = ord($data[$offset]);
        $offset += 1;

        // DestAddr  DestPort
        $ok = Socks5::parseAddressType($request['addr_type'], $request, $data, $offset);
        if (!$ok) {
            logger(LOG_ERR, '[udp] address parse failed, addr_type=' . $request['addr_type']);
            return;
        }

        if ($request['addr_type'] == self::ADDRTYPE_HOST) {
            $request['dest_addr'] = Socks5::getDnsHost($request['dest_addr']);
        }
        if (empty($request['dest_addr'])) {
            logger(LOG_ERR, '[udp] DNS resolve failed for host');
            return;
        }

        $payload = substr($data, $offset);
        if ($payload === '' || $payload === false) {
            logger(LOG_ERR, '[udp] empty payload');
            return;
        }

        logger(LOG_DEBUG, '[udp] relay to ' . $request['dest_addr'] . ':' . $request['dest_port'] . ', payload:' . strlen($payload));
        $header = substr($data, 0, $offset); // 保留头部用于响应
        $remote = new AsyncUdpConnection('udp://' . $request['dest_addr'] . ':' . $request['dest_port']);
        $remote->onConnect = function ($remote) use ($payload) {
            $remote->send($payload);
        };
        $remote->onMessage = function ($remote, $recv) use ($header, $udp_connection) {
            // 回复时加上原始SOCKS5 UDP头
            $udp_connection->send($header . $recv);
            $remote->close();
            unset(self::$udpConnections[spl_object_id($remote)]);
        };
        $remote->onError = function ($remote, $err_code, $err_msg) use ($request) {
            logger(LOG_ERR, '[udp] ' . $request['dest_addr'] . ':' . $request['dest_port'] . " connect fail: {$err_code} {$err_msg}");
            $remote->close();
            unset(self::$udpConnections[spl_object_id($remote)]);
        };
        $remote->connect();
        // 保存udp连接关联，10秒超时
        self::$udpConnections[spl_object_id($remote)] = [$remote, time() + 10, $udp_connection];
        return true;
    }
}
