# socks5-http-proxy
Socks5、Http代理

### Install
    mkdir proxy
    cd proxy
    
    composer require myphps/socks5-http-proxy:dev-master

    
    cp vendor/myphps/socks5-http-proxy/run.example.php run.php
    cp vendor/myphps/socks5-http-proxy/config.example.php config.php
    chmod +x run.php
    
    修改 run.php config.php配置
    运行 ./run.php 

    或者

    1. git clone https://github.com/walkor/socks5-http-proxy
    2. composer install
    
    修改 config.php配置
    运行 ./socks5.php 

### HELP
    ./socks5.php -h

