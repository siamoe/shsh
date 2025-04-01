#!/bin/bash
#
# 这是一个用于VPS初始化和LCMP安装的Shell脚本
# LCMP = Linux + Caddy + MariaDB + PHP
#
# 支持的系统:
# Alpine Linux
#
# Copyright (C) 2023 - 2025 Teddysun <i@teddysun.com>
#
trap _exit INT QUIT TERM

cur_dir="$(cd -P -- "$(dirname -- "$0")" && pwd -P)"

_red() {
    printf '\033[1;31;31m%b\033[0m' "$1"
}

_green() {
    printf '\033[1;31;32m%b\033[0m' "$1"
}

_yellow() {
    printf '\033[1;31;33m%b\033[0m' "$1"
}

_printargs() {
    printf -- "%s" "[$(date)] "
    printf -- "%s" "$1"
    printf "\n"
}

_info() {
    _printargs "$@"
}

_warn() {
    printf -- "%s" "[$(date)] "
    _yellow "$1"
    printf "\n"
}

_error() {
    printf -- "%s" "[$(date)] "
    _red "$1"
    printf "\n"
    exit 2
}

_exit() {
    printf "\n"
    _red "$0 已终止。"
    printf "\n"
    exit 1
}

_exists() {
    local cmd="$1"
    if eval type type >/dev/null 2>&1; then
        eval type "$cmd" >/dev/null 2>&1
    elif command >/dev/null 2>&1; then
        command -v "$cmd" >/dev/null 2>&1
    else
        which "$cmd" >/dev/null 2>&1
    fi
    local rt=$?
    return ${rt}
}

_error_detect() {
    local cmd="$1"
    _info "${cmd}"
    if ! eval "${cmd}" 1>/dev/null; then
        _error "执行命令 (${cmd}) 失败，请检查并重试。"
    fi
}

check_sys() {
    if [ -f /etc/alpine-release ]; then
        return 0
    else
        return 1
    fi
}

get_char() {
    SAVEDSTTY=$(stty -g)
    stty -echo
    stty cbreak
    dd if=/dev/tty bs=1 count=1 2>/dev/null
    stty -raw
    stty echo
    stty "${SAVEDSTTY}"
}

# 检查用户权限
[ ${EUID} -ne 0 ] && _red "此脚本必须以root身份运行！\n" && exit 1

# 检查系统
if ! check_sys; then
    _error "不支持的操作系统，请使用 Alpine Linux 并重试。"
fi

# 在安装前检查系统内存
total_mem=$(free -m | awk '/^Mem:/{print $2}')
if [ $total_mem -lt 512 ]; then
    _warn "系统内存小于512MB，可能会影响性能"
fi

# 添加生成随机密码的函数
generate_random_password() {
    local length=16
    local chars="A-Za-z0-9!@#$%^&*()_+"
    tr -dc "$chars" < /dev/urandom | head -c "$length"
}

# 选择MariaDB版本
while true; do
    echo
    _info "请选择 MariaDB 版本:"
    _info "$(_green 1). MariaDB 10.11"
    _info "$(_green 2). MariaDB 11.4"
    echo
    echo -n "[$(date)] 请输入数字 (默认 1): "
    read mariadb_version
    [ -z "${mariadb_version}" ] && mariadb_version=1
    case "${mariadb_version}" in
        1)
            mariadb_ver="10.11"
            break
            ;;
        2)
            mariadb_ver="11.4"
            break
            ;;
        *)
            _info "输入错误！请只输入数字 1 或 2"
            ;;
    esac
done
echo
_info "---------------------------"
_info "MariaDB 版本 = $(_red "${mariadb_ver}")"
_info "---------------------------"

# 设置MariaDB root密码
echo
_info "请输入MariaDB的root密码:"
echo -n "[$(date)] (回车随机密码): "
read db_pass
if [ -z "${db_pass}" ]; then
    db_pass=$(generate_random_password)
fi
echo
_info "---------------------------"
_info "密码 = $(_red "${db_pass}")"
_info "---------------------------"

# 保存数据库密码到文件
echo "${db_pass}" > /root/.lcmp_db_pass
chmod 600 /root/.lcmp_db_pass

# 选择PHP版本
while true; do
    echo
    _info "请选择 PHP 版本:"
    _info "$(_green 1). PHP 8.0"
    _info "$(_green 2). PHP 8.1"
    _info "$(_green 3). PHP 8.2"
    _info "$(_green 4). PHP 8.3"
    echo
    echo -n "[$(date)] 请输入数字 (默认 3): "
    read php_version
    [ -z "${php_version}" ] && php_version=3
    case "${php_version}" in
        1)
            php_ver="8.0"
            break
            ;;
        2)
            php_ver="8.1"
            break
            ;;
        3)
            php_ver="8.2"
            break
            ;;
        4)
            php_ver="8.3"
            break
            ;;
        *)
            _info "输入错误！请只输入数字 1 2 3 4"
            ;;
    esac
done
_info "---------------------------"
_info "PHP 版本 = $(_red "${php_ver}")"
_info "---------------------------"

_info "按任意键开始...或按 Ctrl+C 取消"
char=$(get_char)

_info "VPS 初始化开始"
_error_detect "rm -f /etc/localtime"
_error_detect "ln -s /usr/share/zoneinfo/Asia/Shanghai /etc/localtime"

# 在脚本开头添加进度显示函数
show_progress() {
    local current=$1
    local total=$2
    local percentage=$((current * 100 / total))
    printf "\r[%-50s] %d%%" "$(printf '#%.0s' $(seq 1 $((percentage/2))))" "$percentage"
}

# 添加系统检查函数
check_system_requirements() {
    _info "正在检查系统要求..."
    
    # 检查内存
    local total_mem=$(free -m | awk '/^Mem:/{print $2}')
    if [ $total_mem -lt 512 ]; then
        _warn "系统内存小于512MB，可能会影响性能"
    else
        _info "系统内存: $(_green "${total_mem}MB")"
    fi
    
    # 检查磁盘空间
    local free_space=$(df -m / | awk 'NR==2 {print $4}')
    if [ $free_space -lt 1024 ]; then
        _warn "可用磁盘空间小于1GB，可能会影响安装"
    else
        _info "可用磁盘空间: $(_green "$((free_space/1024))GB")"
    fi
    
    # 检查CPU核心数
    local cpu_cores=$(nproc)
    _info "CPU核心数: $(_green "${cpu_cores}")"
    
    # 检查系统负载
    local load_avg=$(cat /proc/loadavg | awk '{print $1}')
    _info "系统负载: $(_green "${load_avg}")"
    
    echo
}

# 在开始安装前调用系统检查
check_system_requirements

# 修改安装过程，添加进度显示
_info "开始安装基础包..."
show_progress 1 10
_error_detect "apk update"
show_progress 2 10
_error_detect "apk add --no-cache vim tar zip unzip net-tools bind-tools screen git virt-what wget whois mtr traceroute iftop htop jq tree curl iptables"
show_progress 3 10

_info "安装 Caddy..."
show_progress 4 10
_error_detect "apk add --no-cache caddy"
show_progress 5 10

_info "安装 MariaDB..."
show_progress 6 10
_error_detect "apk add --no-cache mariadb mariadb-client mariadb-server-utils"
show_progress 7 10

_info "安装 PHP ${php_ver}..."
show_progress 8 10
# PHP安装部分保持不变
php_pkg_ver="${php_ver/./}"  # 转换版本号，例如：8.3 -> 83

# 安装PHP主要组件
_error_detect "apk add --no-cache php${php_pkg_ver} php${php_pkg_ver}-fpm"

# 安装PHP扩展
php_extensions="mysqli json openssl curl zlib xml phar intl dom xmlreader ctype session mbstring gd opcache pdo pdo_mysql tokenizer fileinfo redis"
for ext in ${php_extensions}; do
    _error_detect "apk add --no-cache php${php_pkg_ver}-${ext}"
done

# 安装Redis服务器（可选，如果需要本地Redis服务器）
_error_detect "apk add --no-cache redis"
_error_detect "rc-update add redis default"
_error_detect "/etc/init.d/redis start"

# 安装ICU数据包
_error_detect "apk add --no-cache icu-data-full"
_info "PHP ${php_ver} 及扩展安装完成"

# 创建必要的目录
_error_detect "mkdir -p /data/www/default"
_error_detect "mkdir -p /var/log/caddy/"
_error_detect "mkdir -p /etc/caddy/conf.d/"
_error_detect "chown -R caddy:caddy /var/log/caddy/"

# 在脚本开头添加 MariaDB 别名设置
cat > /etc/profile.d/mariadb_aliases.sh <<EOF
alias mysql=mariadb
alias mysqld_safe=mariadbd-safe
alias mysqladmin=mariadbd-admin
EOF

source /etc/profile.d/mariadb_aliases.sh

# 在修改配置前添加备份
cp /etc/caddy/Caddyfile /etc/caddy/Caddyfile.bak

# 修改 Caddy 配置，使用最简单的配置
cat >/etc/caddy/Caddyfile <<EOF
{
    admin off
}

import /etc/caddy/conf.d/*.conf
EOF

# 修改默认站点配置
cat >/etc/caddy/conf.d/default.conf <<EOF
:80 {
	header {
		Strict-Transport-Security "max-age=31536000; preload"
		X-Content-Type-Options nosniff
		X-Frame-Options SAMEORIGIN
	}
	root * /data/www/default
	encode gzip
	php_fastcgi unix//run/php-fpm.sock
	file_server {
		index index.html
	}
	log {
		output file /var/log/caddy/access.log {
			roll_size 100mb
			roll_keep 3
			roll_keep_for 7d
		}
	}
}
EOF

# 配置MariaDB
cat >/etc/my.cnf.d/server.cnf <<EOF
[mysqld]
bind-address = 0.0.0.0
port = 3306
skip-networking = 0
innodb_buffer_pool_size = 256M
max_allowed_packet = 1024M
net_read_timeout = 3600
net_write_timeout = 3600
character-set-server = utf8mb4

[client-mariadb]
default-character-set = utf8mb4
EOF

# PHP-FPM配置部分
php_fpm_conf="/etc/php${php_pkg_ver}/php-fpm.d/www.conf"
php_ini="/etc/php${php_pkg_ver}/php.ini"

# 确保目录存在
_error_detect "mkdir -p /var/log/php${php_pkg_ver}"
_error_detect "mkdir -p /run"
_error_detect "chown -R caddy:caddy /var/log/php${php_pkg_ver}"

# 修改PHP-FPM配置
cat > ${php_fpm_conf} <<EOF
[www]
user = caddy
group = caddy
listen = /run/php-fpm.sock
listen.owner = caddy
listen.group = caddy
listen.mode = 0660

pm = dynamic
pm.max_children = 10
pm.start_servers = 4
pm.min_spare_servers = 2
pm.max_spare_servers = 6

php_admin_value[error_log] = /var/log/php${php_pkg_ver}/error.log
php_admin_flag[log_errors] = on
EOF

# 确保PHP-FPM服务正确启动
start_php_fpm() {
    local max_attempts=3
    local attempt=1
    
    while [ $attempt -le $max_attempts ]; do
        _info "正在启动 PHP-FPM 服务，尝试 ${attempt}/${max_attempts}"
        
        # 停止服务（如果正在运行）
        /etc/init.d/php-fpm${php_pkg_ver} stop >/dev/null 2>&1
        
        # 删除旧的 socket 文件（如果存在）
        rm -f /run/php-fpm.sock
        
        # 启动服务
        /etc/init.d/php-fpm${php_pkg_ver} start
        
        # 等待 socket 文件创建
        sleep 2
        
        if [ -S /run/php-fpm.sock ]; then
            _info "PHP-FPM 服务启动成功"
            # 确保 socket 权限正确
            chown caddy:caddy /run/php-fpm.sock
            chmod 660 /run/php-fpm.sock
            return 0
        fi
        
        _warn "PHP-FPM 启动失败，正在重试..."
        attempt=$((attempt + 1))
        sleep 1
    done
    
    _error "PHP-FPM 服务启动失败"
    return 1
}

# 在服务启动部分调用此函数
_error_detect "start_php_fpm"

# 验证服务状态
verify_services() {
    local error=0
    
    # 检查PHP-FPM
    if [ ! -S /run/php-fpm.sock ]; then
        _red "PHP-FPM socket不存在\n"
        error=1
    else
        _green "PHP-FPM socket正常\n"
    fi
    
    # 检查PHP-FPM进程
    if ! pgrep -f "php-fpm: master" >/dev/null; then
        _red "PHP-FPM主进程未运行\n"
        error=1
    else
        _green "PHP-FPM主进程运行正常\n"
    fi
    
    if [ $error -eq 1 ]; then
        _warn "检查PHP-FPM错误日志:"
        tail -n 10 /var/log/php${php_pkg_ver}/error.log
    fi
    
    return $error
}

# 停止MariaDB服务
/etc/init.d/mariadb stop

# 删除旧的数据库文件
rm -rf /var/lib/mysql/*

# 重新初始化MariaDB
/etc/init.d/mariadb setup

# 启动MariaDB服务
/etc/init.d/mariadb start

# 建议添加等待时间
sleep 5

# 设置root密码
/usr/bin/mariadb -u root <<EOF
ALTER USER 'root'@'localhost' IDENTIFIED BY '${db_pass}';
FLUSH PRIVILEGES;
EOF

# 更新密码文件
echo "${db_pass}" > /root/.lcmp_db_pass
chmod 600 /root/.lcmp_db_pass

# 安装phpMyAdmin
_error_detect "wget -qO pma.tar.gz https://dl.lamp.sh/files/pma.tar.gz"
_error_detect "tar zxf pma.tar.gz -C /data/www/default/"
_error_detect "rm -f pma.tar.gz"
/usr/bin/mariadb -uroot -p"${db_pass}" </data/www/default/pma/sql/create_tables.sql

# 设置目录权限
_error_detect "chown -R caddy:caddy /data/www"

# 添加服务到开机启动（修改这部分）
_error_detect "rc-update add mariadb default"
_error_detect "rc-update add php-fpm${php_pkg_ver} default"
_error_detect "rc-update add caddy default"

# 在启动 Caddy 之前添加配置验证
verify_caddy_config() {
    if ! caddy validate --config /etc/caddy/Caddyfile; then
        _error "Caddy 配置验证失败"
    fi
    # 格式化配置文件
    caddy fmt --overwrite /etc/caddy/Caddyfile
}

# 在重启 Caddy 之前验证配置
_error_detect "verify_caddy_config"
_error_detect "/etc/init.d/caddy restart"

# 添加服务状态检查函数（放在脚本开头的函数定义部分）
check_service_status() {
    local service=$1
    if /etc/init.d/${service} status >/dev/null 2>&1; then
        _green "${service} 运行正常\n"
        return 0
    else
        _red "${service} 运行异常\n"
        return 1
    fi
}

# 添加创建默认页面的函数
create_default_page() {
    local default_page="/data/www/default/index.php"
    cat > ${default_page} << 'EOF'
<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>LCMP - Alpine Linux</title>
    <style>
        body {
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
            line-height: 1.6;
            margin: 0;
            padding: 20px;
            background: #f5f5f5;
        }
        .container {
            max-width: 1000px;
            margin: 0 auto;
            background: white;
            padding: 20px;
            border-radius: 8px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }
        h1 { color: #2c3e50; border-bottom: 2px solid #eee; padding-bottom: 10px; }
        .info-section { margin: 20px 0; }
        .info-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
            gap: 20px;
            margin-top: 20px;
        }
        .info-box {
            background: #f8f9fa;
            padding: 15px;
            border-radius: 6px;
            border: 1px solid #dee2e6;
        }
        .info-box h3 { margin-top: 0; color: #0056b3; }
        table { width: 100%; border-collapse: collapse; }
        th, td { padding: 8px; text-align: left; border-bottom: 1px solid #ddd; }
        th { background-color: #f8f9fa; }
        .success { color: #28a745; }
        .warning { color: #ffc107; }
        .error { color: #dc3545; }
    </style>
</head>
<body>
    <div class="container">
        <h1>LCMP - Alpine Linux 服务器信息</h1>
        <div class="info-grid">
            <div class="info-box">
                <h3>系统信息</h3>
                <table>
                    <tr>
                        <td>操作系统</td>
                        <td><?php 
                            $os = '';
                            if (file_exists('/etc/os-release')) {
                                $os_info = parse_ini_file('/etc/os-release');
                                $os = isset($os_info['PRETTY_NAME']) ? $os_info['PRETTY_NAME'] : '';
                            }
                            if (empty($os)) {
                                $os = php_uname('s') . ' ' . php_uname('r');
                            }
                            echo htmlspecialchars($os);
                        ?></td>
                    </tr>
                    <tr><td>服务器时间</td><td><?php echo date('Y-m-d H:i:s'); ?></td></tr>
                    <tr><td>服务器IP</td><td><?php 
                        // 获取非环回地址的IPv4
                        $ip_command = 'ip -4 addr show scope global | grep -oP "(?<=inet ).*(?=/)" | head -1';
                        $server_ip = trim(shell_exec($ip_command));
                        
                        // 如果为空或是本地地址，尝试其他方法
                        if (empty($server_ip) || $server_ip == '127.0.0.1' || strpos($server_ip, '192.168.') === 0) {
                            // 尝试通过外部服务获取公网IP
                            $server_ip = trim(shell_exec('curl -s --connect-timeout 5 ip.sb'));
                            
                            // 备选的外部服务
                            if (empty($server_ip) || $server_ip == '127.0.0.1') {
                                $server_ip = trim(shell_exec('curl -s --connect-timeout 5 ifconfig.me'));
                            }
                            
                            // 再尝试一个备选
                            if (empty($server_ip) || $server_ip == '127.0.0.1') {
                                $server_ip = trim(shell_exec('curl -s --connect-timeout 5 ident.me'));
                            }
                        }
                        
                        // 最后尝试服务器变量
                        if (empty($server_ip) || $server_ip == '127.0.0.1') {
                            if (!empty($_SERVER['SERVER_ADDR']) && $_SERVER['SERVER_ADDR'] != '127.0.0.1') {
                                $server_ip = $_SERVER['SERVER_ADDR'];
                            } elseif (!empty($_SERVER['HTTP_HOST']) && $_SERVER['HTTP_HOST'] != 'localhost') {
                                $server_ip = $_SERVER['HTTP_HOST'];
                            }
                        }
                        
                        echo htmlspecialchars($server_ip && $server_ip != '127.0.0.1' ? $server_ip : '无法获取外部IP');
                    ?></td></tr>
                </table>
            </div>
            <div class="info-box">
                <h3>PHP信息</h3>
                <table>
                    <tr><td>PHP版本</td><td><?php echo PHP_VERSION; ?></td></tr>
                    <tr><td>PHP运行模式</td><td><?php echo php_sapi_name(); ?></td></tr>
                    <tr><td>Zend引擎版本</td><td><?php echo zend_version(); ?></td></tr>
                </table>
            </div>
            <div class="info-box">
                <h3>数据库信息</h3>
                <table>
                    <?php
                    try {
                        $pdo = new PDO('mysql:host=localhost', 'root', trim(file_get_contents('/root/.lcmp_db_pass')));
                        $version = $pdo->query('SELECT VERSION()')->fetchColumn();
                        echo "<tr><td>MariaDB版本</td><td class='success'>{$version}</td></tr>";
                        echo "<tr><td>连接状态</td><td class='success'>正常</td></tr>";
                    } catch (PDOException $e) {
                        echo "<tr><td>数据库状态</td><td class='error'>连接失败</td></tr>";
                    }
                    ?>
                </table>
            </div>
            <div class="info-box">
                <h3>Redis信息</h3>
                <table>
                    <?php
                    if (extension_loaded('redis')) {
                        try {
                            $redis = new Redis();
                            $redis->connect('127.0.0.1', 6379);
                            $info = $redis->info();
                            echo "<tr><td>Redis版本</td><td class='success'>{$info['redis_version']}</td></tr>";
                            echo "<tr><td>连接状态</td><td class='success'>正常</td></tr>";
                            echo "<tr><td>内存使用</td><td>" . format_bytes($info['used_memory']) . "</td></tr>";
                        } catch (Exception $e) {
                            echo "<tr><td>Redis状态</td><td class='error'>连接失败</td></tr>";
                        }
                    } else {
                        echo "<tr><td>Redis扩展</td><td class='warning'>未安装</td></tr>";
                    }
                    ?>
                </table>
            </div>
        </div>
        <div class="info-section">
            <h3>已加载的PHP扩展</h3>
            <div style="display: grid; grid-template-columns: repeat(auto-fill, minmax(200px, 1fr)); gap: 10px;">
                <?php
                $extensions = get_loaded_extensions();
                sort($extensions);
                foreach ($extensions as $ext) {
                    $version = phpversion($ext);
                    echo "<div class='info-box' style='margin: 0;'>";
                    echo "<strong>{$ext}</strong>";
                    echo $version ? "<br><small>v{$version}</small>" : "";
                    echo "</div>";
                }
                ?>
            </div>
        </div>
    </div>
    <?php
    function format_bytes($bytes) {
        $units = ['B', 'KB', 'MB', 'GB'];
        $bytes = max($bytes, 0);
        $pow = floor(($bytes ? log($bytes) : 0) / log(1024));
        $pow = min($pow, count($units) - 1);
        $bytes /= pow(1024, $pow);
        return round($bytes, 2) . ' ' . $units[$pow];
    }
    ?>
</body>
</html>
EOF

    chown caddy:caddy ${default_page}
    chmod 644 ${default_page}
}

# 在安装完成部分添加创建默认页面的调用（在安装完成前）
create_default_page

# 显示安装信息
_info "安装信息:"
_info "------------------------"
_info "MariaDB 版本: $(_green "$(mariadb --version | awk '{print $3}' | cut -d'-' -f1)")"
_info "PHP 版本: $(_green "$(/usr/bin/php${php_pkg_ver} -v | head -n1 | cut -d' ' -f2)")"
_info "Caddy 版本: $(_green "$(caddy version | head -n1)")"
_info "Redis 版本: $(_green "$(redis-server --version | cut -d' ' -f3)")"
_info "------------------------"
_info "服务状态:"
check_service_status mariadb
check_service_status "php-fpm${php_pkg_ver}"
check_service_status caddy

# 验证服务是否正常运行
verify_services

# 建议添加基本防火墙规则
iptables -A INPUT -p tcp --dport 80 -j ACCEPT
iptables -A INPUT -p tcp --dport 443 -j ACCEPT

_info "------------------------"
_info "Web根目录: $(_green "/data/www")"
_info "默认站点: $(_green "http://$(curl -s ip.sb)")"
_info "phpMyAdmin: $(_green "http://$(curl -s ip.sb)/pma/")"
_info "MariaDB root密码: $(_green "${db_pass}")"
_info "------------------------"
_info "管理命令: lcmp"
_info "使用方法: lcmp help"
_info "------------------------"

# 创建LCMP管理脚本
cat >/usr/local/bin/lcmp <<'EOF'
#!/bin/bash

# 辅助函数定义
_red() {
    printf '\033[1;31;31m%b\033[0m' "$1"
}

_green() {
    printf '\033[1;31;32m%b\033[0m' "$1"
}

_yellow() {
    printf '\033[1;31;33m%b\033[0m' "$1"
}

_info() {
    printf -- "%s" "[$(date)] "
    printf -- "%s" "$1"
    printf "\n"
}

_warn() {
    printf -- "%s" "[$(date)] "
    _yellow "$1"
    printf "\n"
}

_error() {
    printf -- "%s" "[$(date)] "
    _red "$1"
    printf "\n"
    exit 2
}

_error_detect() {
    local cmd="$1"
    _info "${cmd}"
    if ! eval "${cmd}" 1>/dev/null; then
        _error "执行命令 (${cmd}) 失败，请检查并重试。"
    fi
}

# 验证服务启动函数
verify_service_start() {
    local service=$1
    local max_attempts=5
    local attempt=1
    
    while [ $attempt -le $max_attempts ]; do
        if /etc/init.d/${service} status >/dev/null 2>&1; then
            return 0
        fi
        _info "等待服务 ${service} 启动，尝试 ${attempt}/${max_attempts}"
        sleep 2
        attempt=$((attempt + 1))
    done
    
    _error "服务 ${service} 启动失败"
    return 1
}

# 检查服务状态函数
check_service_status() {
    local service=$1
    if /etc/init.d/${service} status >/dev/null 2>&1; then
        _green "${service} 运行正常\n"
        return 0
    else
        _red "${service} 运行异常\n"
        return 1
    fi
}

# 检查端口函数
check_port() {
    local port=$1
    local service=$2
    if netstat -tnl | grep -E ":(${port})\s" >/dev/null 2>&1; then
        _green "${service}已监听${port}端口\n"
        return 0
    else
        if netstat -tnl | grep -E "::.*:${port}\s" >/dev/null 2>&1; then
            _green "${service}已监听${port}端口(IPv6)\n"
            return 0
        else
            _red "${service}未监听${port}端口\n"
            return 1
        fi
    fi
}

show_help() {
    echo "LCMP 管理工具"
    echo
    echo "用法: lcmp [命令] [参数]"
    echo
    echo "系统状态命令:"
    echo "  status                     显示所有服务状态"
    echo "  status:web                 显示网站相关服务状态"
    echo "  status:db                  显示数据库状态"
    echo
    echo "服务管理命令:"
    echo "  restart                    重启所有服务"
    echo "  restart:web                重启Web服务(Caddy + PHP-FPM)"
    echo "  restart:db                 重启数据库服务"
    echo "  restart:redis              重启Redis服务"
    echo
    echo "网站管理命令:"
    echo "  add    <域名>              添加新网站"
    echo "  del    <域名>              删除网站"
    echo "  list                       列出所有网站"
    echo
    echo "数据库管理命令:"
    echo "  db:create  <数据库名>      创建新数据库"
    echo "  db:delete  <数据库名>      删除数据库"
    echo "  db:list                    列出所有数据库"
    echo
    echo "帮助信息:"
    echo "  help                       显示此帮助信息"
    echo
    echo "示例:"
    echo "  lcmp add example.com"
    echo "  lcmp db:create mydb"
    echo "  lcmp restart:web"
}

# 添加重启服务函数
restart_services() {
    _info "正在重启所有服务..."
    
    # 重启MariaDB
    _info "重启 MariaDB..."
    /etc/init.d/mariadb restart
    sleep 2
    
    # 重启PHP-FPM
    local php_ver=$(php -v | head -n1 | cut -d' ' -f2 | cut -d'.' -f1,2 | tr -d '.')
    _info "重启 PHP-FPM..."
    /etc/init.d/php-fpm${php_ver} restart
    sleep 2
    
    # 重启Redis
    _info "重启 Redis..."
    /etc/init.d/redis restart
    sleep 2
    
    # 重启Caddy
    _info "重启 Caddy..."
    /etc/init.d/caddy restart
    
    _info "所有服务重启完成"
    show_status
}

restart_web_services() {
    _info "正在重启Web服务..."
    
    # 重启PHP-FPM
    local php_ver=$(php -v | head -n1 | cut -d' ' -f2 | cut -d'.' -f1,2 | tr -d '.')
    _info "重启 PHP-FPM..."
    /etc/init.d/php-fpm${php_ver} restart
    sleep 2
    
    # 重启Caddy
    _info "重启 Caddy..."
    /etc/init.d/caddy restart
    
    _info "Web服务重启完成"
    show_web_status
}

restart_db_service() {
    _info "正在重启数据库服务..."
    
    # 重启MariaDB
    _info "重启 MariaDB..."
    /etc/init.d/mariadb restart
    
    _info "数据库服务重启完成"
    show_db_status
}

restart_redis_service() {
    _info "正在重启Redis服务..."
    
    # 重启Redis
    _info "重启 Redis..."
    /etc/init.d/redis restart
    
    _info "Redis服务重启完成"
    check_service_status redis
}

add_site() {
    local domain=$1
    if [ -z "${domain}" ]; then
        _red "请指定域名!\n"
        return 1
    fi
    
    # 创建网站目录
    mkdir -p "/data/www/${domain}"
    chown -R caddy:caddy "/data/www/${domain}"
    
    # 创建网站配置
    cat > "/etc/caddy/conf.d/${domain}.conf" <<CONF
${domain} {
    header {
        Strict-Transport-Security "max-age=31536000; preload"
        X-Content-Type-Options nosniff
        X-Frame-Options SAMEORIGIN
    }
    root * /data/www/${domain}
    encode gzip
    php_fastcgi unix//run/php-fpm.sock
    file_server {
        index index.html index.php
    }
    log {
        output file /var/log/caddy/${domain}.log {
            roll_size 100mb
            roll_keep 3
            roll_keep_for 7d
        }
    }
}
CONF
    
    # 创建默认首页
    cat > "/data/www/${domain}/index.php" <<PHP
<!DOCTYPE html>
<html>
<head>
    <title>Welcome to ${domain}</title>
</head>
<body>
    <h1>Welcome to ${domain}</h1>
    <p>PHP Version: <?php echo PHP_VERSION; ?></p>
</body>
</html>
PHP
    
    # 重启Caddy服务
    /etc/init.d/caddy restart
    
    _green "网站 ${domain} 添加成功!\n"
}

del_site() {
    local domain=$1
    if [ -z "${domain}" ]; then
        _red "请指定域名!\n"
        return 1
    fi
    
    # 删除网站目录和配置
    rm -rf "/data/www/${domain}"
    rm -f "/etc/caddy/conf.d/${domain}.conf"
    rm -f "/var/log/caddy/${domain}.log"*
    
    # 重启Caddy服务
    /etc/init.d/caddy restart
    
    _green "网站 ${domain} 删除成功!\n"
}

list_sites() {
    echo "已配置的网站:"
    echo "------------------------"
    for conf in /etc/caddy/conf.d/*.conf; do
        if [ -f "${conf}" ] && [ "${conf}" != "/etc/caddy/conf.d/default.conf" ]; then
            domain=$(basename "${conf}" .conf)
            echo "${domain}"
        fi
    done
    echo "------------------------"
}

show_status() {
    _info "系统状态信息:"
    _info "------------------------"
    
    # 显示系统负载
    _info "系统负载: $(_green "$(uptime | awk -F'load average:' '{print $2}')")"
    
    # 显示内存使用
    _info "内存使用:"
    free -h | grep -v + | sed 's/^/  /'
    
    # 显示磁盘使用
    _info "磁盘使用:"
    df -h / /data | sed 's/^/  /'
    
    # 显示服务状态
    _info "服务状态:"
    check_service_status mariadb
    check_service_status "php-fpm$(php -v | head -n1 | cut -d' ' -f2 | cut -d'.' -f1,2 | tr -d '.')"
    check_service_status caddy
    check_service_status redis
    
    # 显示端口监听
    _info "端口监听:"
    netstat -tnlp | grep -E ':(80|443|3306|6379)' | sed 's/^/  /'
    
    # 显示PHP信息
    _info "PHP 版本: $(_green "$(php -v | head -n1 | cut -d' ' -f2)")"
    _info "PHP-FPM 进程: $(_green "$(ps aux | grep 'php-fpm' | grep -v grep | wc -l)")"
    
    # 显示数据库信息
    local db_password=$(cat /root/.lcmp_db_pass)
    _info "数据库状态:"
    mariadb -uroot -p"${db_password}" -e "SHOW STATUS LIKE '%Threads_connected%';" 2>/dev/null | sed 's/^/  /'
    
    # 显示网站信息
    _info "已配置网站:"
    for conf in /etc/caddy/conf.d/*.conf; do
        if [ -f "${conf}" ] && [ "${conf}" != "/etc/caddy/conf.d/default.conf" ]; then
            echo "  $(basename "${conf}" .conf)"
        fi
    done
    
    _info "------------------------"
}

show_web_status() {
    _info "Web服务状态:"
    _info "------------------------"
    
    # 检查Caddy状态
    _info "Caddy状态:"
    check_service_status caddy
    _info "监听端口:"
    netstat -tnlp | grep caddy | sed 's/^/  /'
    
    # 检查PHP-FPM状态
    _info "PHP-FPM状态:"
    local php_ver=$(php -v | head -n1 | cut -d' ' -f2 | cut -d'.' -f1,2 | tr -d '.')
    check_service_status "php-fpm${php_ver}"
    _info "PHP-FPM进程:"
    ps aux | grep 'php-fpm' | grep -v grep | sed 's/^/  /'
    
    # 检查网站配置
    _info "网站配置:"
    for conf in /etc/caddy/conf.d/*.conf; do
        if [ -f "${conf}" ]; then
            echo "  - $(basename "${conf}")"
        fi
    done
    
    _info "------------------------"
}

show_db_status() {
    _info "数据库状态:"
    _info "------------------------"
    
    # 检查MariaDB状态
    check_service_status mariadb
    
    # 显示数据库详细信息
    local db_password=$(cat /root/.lcmp_db_pass)
    if mariadb -uroot -p"${db_password}" -e "SELECT VERSION();" >/dev/null 2>&1; then
        _info "数据库版本: $(_green "$(mariadb -V | awk '{print $5}' | cut -d',' -f1)")"
        
        # 显示数据库统计信息
        _info "数据库统计:"
        mariadb -uroot -p"${db_password}" -e "
        SELECT table_schema AS '数据库名',
        ROUND(SUM(data_length + index_length) / 1024 / 1024, 2) AS '大小(MB)'
        FROM information_schema.tables
        GROUP BY table_schema;" 2>/dev/null | sed 's/^/  /'
        
        # 显示连接信息
        _info "当前连接数:"
        mariadb -uroot -p"${db_password}" -e "SHOW STATUS LIKE '%Threads_connected%';" 2>/dev/null | sed 's/^/  /'
        
        # 显示数据库运行时间
        _info "运行时间:"
        mariadb -uroot -p"${db_password}" -e "SHOW STATUS LIKE 'Uptime';" 2>/dev/null | sed 's/^/  /'
    else
        _red "无法连接到数据库\n"
    fi
    
    _info "------------------------"
}

# 数据库管理函数
create_database() {
    local db_name=$1
    if [ -z "${db_name}" ]; then
        _red "请指定数据库名!\n"
        return 1
    fi
    
    # 获取数据库密码
    local db_password=$(cat /root/.lcmp_db_pass)
    
    # 生成数据库用户和密码
    local db_user="${db_name}_user"
    local user_password=$(tr -dc 'A-Za-z0-9!@#$%^&*()_+' < /dev/urandom | head -c 12)
    
    # 创建数据库
    _info "正在创建数据库 ${db_name}..."
    if mariadb -uroot -p"${db_password}" -e "CREATE DATABASE IF NOT EXISTS \`${db_name}\` CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci;" 2>/dev/null; then
        _green "数据库 ${db_name} 创建成功!\n"
        
        # 创建用户并授权
        _info "正在创建数据库用户并分配权限..."
        if mariadb -uroot -p"${db_password}" -e "CREATE USER IF NOT EXISTS '${db_user}'@'localhost' IDENTIFIED BY '${user_password}'; GRANT ALL PRIVILEGES ON \`${db_name}\`.* TO '${db_user}'@'localhost'; FLUSH PRIVILEGES;" 2>/dev/null; then
            _green "用户创建成功!\n"
            _info "---------------------------"
            _info "数据库名: $(_green "${db_name}")"
            _info "用户名: $(_green "${db_user}")"
            _info "密码: $(_green "${user_password}")"
            _info "---------------------------"
            _info "请妥善保管以上信息!"
            
            # 保存数据库信息到文件
            echo "数据库: ${db_name}" > "/root/.${db_name}_info"
            echo "用户名: ${db_user}" >> "/root/.${db_name}_info"
            echo "密码: ${user_password}" >> "/root/.${db_name}_info"
            chmod 600 "/root/.${db_name}_info"
            _info "信息已保存至: $(_green "/root/.${db_name}_info")"
        else
            _red "用户创建失败!\n"
            return 1
        fi
    else
        _red "数据库 ${db_name} 创建失败!\n"
        return 1
    fi
}

delete_database() {
    local db_name=$1
    if [ -z "${db_name}" ]; then
        _red "请指定数据库名!\n"
        return 1
    fi
    
    # 获取数据库密码
    local db_password=$(cat /root/.lcmp_db_pass)
    
    # 确认操作
    _red "警告: 此操作将永久删除数据库 ${db_name} 及其所有数据!\n"
    _yellow "确认删除? [y/N]: "
    read -r confirm
    if [ "${confirm,,}" != "y" ]; then
        _info "操作已取消"
        return 0
    fi
    
    # 删除数据库
    _info "正在删除数据库 ${db_name}..."
    if mariadb -uroot -p"${db_password}" -e "DROP DATABASE IF EXISTS \`${db_name}\`;" 2>/dev/null; then
        _green "数据库 ${db_name} 删除成功!\n"
    else
        _red "数据库 ${db_name} 删除失败!\n"
        return 1
    fi
}

list_databases() {
    # 获取数据库密码
    local db_password=$(cat /root/.lcmp_db_pass)
    
    # 列出所有数据库
    _info "数据库列表:"
    _info "------------------------"
    if ! mariadb -uroot -p"${db_password}" -e "SHOW DATABASES;" 2>/dev/null; then
        _red "无法连接到数据库服务器!\n"
        return 1
    fi
    _info "------------------------"
}

# case 语句部分保持不变
case "$1" in
    status)
        show_status
        ;;
    status:web)
        show_web_status
        ;;
    status:db)
        show_db_status
        ;;
    restart)
        restart_services
        ;;
    restart:web)
        restart_web_services
        ;;
    restart:db)
        restart_db_service
        ;;
    restart:redis)
        restart_redis_service
        ;;
    add)
        add_site "$2"
        ;;
    del)
        del_site "$2"
        ;;
    list)
        list_sites
        ;;
    db:create)
        create_database "$2"
        ;;
    db:delete)
        delete_database "$2"
        ;;
    db:list)
        list_databases
        ;;
    help|--help|-h)
        show_help
        ;;
    *)
        show_help
        exit 1
        ;;
esac
EOF

# 设置权限
chmod +x /usr/local/bin/lcmp

# 添加进度显示函数
show_progress() {
    local current=$1
    local total=$2
    local percentage=$((current * 100 / total))
    printf "\r[%-50s] %d%%" "$(printf '#%.0s' $(seq 1 $((percentage/2))))" "$percentage"
}

# 在php.ini中添加安全设置
sed -i 's/display_errors = On/display_errors = Off/' /etc/php${php_pkg_ver}/php.ini

# 添加logrotate配置
cat > /etc/logrotate.d/lcmp <<EOF
/var/log/caddy/*.log {
    daily
    rotate 7
    compress
    delaycompress
    missingok
    notifempty
    create 0640 caddy caddy
}
EOF

# 添加简单的监控脚本
cat > /usr/local/bin/lcmp-monitor <<EOF
#!/bin/bash
# 监控服务状态
# 监控磁盘使用
# 监控内存使用
EOF