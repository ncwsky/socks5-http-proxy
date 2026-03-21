<?php

return [
    'common' => [
        "auth" => false,
        'user' => 'user',
        'pass' => 'pass',
        'ens_key' => '', //数据加密key 连接端必需为中断模式并配置相同的 key，否则设置此值非中断端的连接将无法解析数据
        "debug" => false,
        "tcp_port" => 1081,
        "udp_port" => 0, //设置为0时同tcp_port
        "wan_ip" => '10.0.0.246', //对外IP用于udp服务
    ],
    'relay' => [ //中继
        'endpoint' => '', // ip:port
        'gzip' => 0, // 1启用gzip压缩传输 两端需配置相同
        'ens_key' => '', // 加密key 需要和socks5服务端的common.ens_key值相同
    ]
];
