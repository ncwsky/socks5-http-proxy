<?php
return [
    'common'=>[
        "auth" => false,//METHOD_USER_PASS
        'user' => 'user',
        'pass' => 'pass',
        'ens_key'=>'', //数据加密key
        "log_level" => LOG_DEBUG,
        "tcp_port" => 1082,
        "udp_port" => 0, //设置为0 表示由系统动态分配
        "wan_ip" => '',
    ],
    'relay' => [ //中继
        'endpoint' => '192.168.0.245:1081', // http[s]://xxx, ws://xxx, tcp://xxx
        'gzip_min'=> 1024, //1k
        'gzip_level' => 0, // 0-9 0不压缩
        'ens_key' => '83bca0d49ceb23ae7e9cd45e', // 加密key
    ],
    'relay_' => [ //中继
        'endpoint' => '101.34.239.18:1081', // http[s]://xxx, ws://xxx, tcp://xxx
        'gzip_min'=> 1024, //1k
        'gzip_level' => 0, // 0-9 0不压缩
        'ens_key' => 'arcxeqwQP5lcSBor5vEUAyaTMdBvT4I5hRUKIPcdzEE', // 加密key
    ]
];
