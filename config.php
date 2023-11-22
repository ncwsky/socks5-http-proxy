<?php
return [
    'common'=>[
        "auth" => false,
        'user' => 'user',
        'pass' => 'pass',
        'ens_key'=>'', //数据加密key
        "log_level" => LOG_DEBUG,
        "tcp_port" => 1081,
        "udp_port" => 0, //设置为0时同tcp_port
        "wan_ip" => '192.168.0.245', //对外IP用于udp服务
    ],
    'relay' => [ //中继
        'endpoint' => '', // ip:port
        'ens_key' => '', // 加密key
    ]
];
