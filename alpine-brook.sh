#!/usr/bin/env bash

source /etc/os-release

function check_parameter(){
    if [[ "$#" -ne 2 ]]; then
        printf "脚本运行参数有误，请重新运行脚本\033[0m\n"
	    exit 1
    else
        [[ "$1" -lt 1 || "$1" -gt 65535 ]] && printf "本地监听端口参数有误，纠正参考：0-65535范围内，请重新运行本脚本\033[0m\n"&& exit 1;
	    ! [[ "$2" =~ : ]] && printf "第2个参数有误，纠正参考：1.2.3.4:3000\033[0m\n" && exit 1;
	    check_ip "$(echo "$2" | awk -F : '{print $1}')"
        [[ $(echo "$2" | awk -F : '{print $2}') -lt 1 || $(echo "$2" | awk -F : '{print $2}') -gt 65535 ]] && printf "远程转发端口有误，纠正参考：0-65535范围内，请重新运行本脚本\033[0m\n"&& exit 1;
        if ! command -v netstat >/dev/null 2>&1; then
            if [[ "$ID" = "centos" ]]; then
                yum install net-tools -y
            elif [[ "$ID" = "alpine" ]]; then
                apk add --no-cache net-tools
            else
                apt install net-tools -y
            fi
        fi
        if netstat -tlpn | grep -w "$1" >/dev/null 2>&1; then
            printf "\n"
            printf "检测到本地 %s 端口已被占用，安装退出\033[0m\n" "$1"
            exit 1
        fi
    fi
}

function check_os(){
    if [[ "$ID" != "centos" && "$ID" != "debian" && "$ID" != "ubuntu" && "$ID" != "almalinux" && "$ID" != "rocky" && "$ID" != "alpine" ]]; then
        printf "脚本不支持%s系统，安装中断\033[0m\n" "$ID"
        exit 1
    elif [[ "$ID" == "centos" && "$VERSION_ID" -lt "7" ]]; then
        printf "脚本不支持CentOS %s，安装中断\033[0m\n" "$VERSION_ID"
        exit 1
    elif [[ "$ID" == "debian" && "$VERSION_ID" -lt "8" ]]; then
        printf "脚本不支持Debian %s，安装中断\033[0m\n" "$VERSION_ID"
        exit 1
    elif [[ "$ID" == "ubuntu" && $(echo "$VERSION_ID" | cut -d '.' -f1) -lt "16" ]]; then
        printf "脚本不支持Ubuntu %s，安装中断\033[0m\n" "$VERSION_ID"
        exit 1
    elif [[ "$ID" == "alpine" ]]; then
        if ! command -v wget >/dev/null 2>&1; then
            apk add --no-cache wget
        fi
        # 其他 Alpine 特有的依赖项安装
    fi
    if command -v sestatus >/dev/null 2>&1; then
        if [[ "$(getenforce)" == "Enforcing" ]]; then
            sed -i 's#SELINUX=enforcing#SELINUX=disabled#g' /etc/selinux/config
            setenforce 0
        fi
    fi
}

function check_ip() {   
    IP="$1"
    VALID_CHECK=$(echo "$IP" |awk -F. '$1<=255&&$2<=255&&$3<=255&&$4<=255{print "yes"}')   
    if echo "$IP" |grep -E "^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$">/dev/null; then   
        [[ ${VALID_CHECK:-no} != "yes" ]] && printf "远程转发IP %s 有误，安装中断\033[0m\n" "$IP" && exit 1; 
    else   
        printf "远程转发IP %s 有误，安装中断\033[0m\n" "$IP" 
        exit 1
    fi  
} 

function down_brook(){
    if ! command -v brook >/dev/null 2>&1; then
	    new_ver=$(wget -qO- https://api.github.com/repos/txthinking/brook/releases| grep "tag_name"| head -n 1| awk -F ":" '{print $2}'| sed 's/\"//g;s/,//g;s/ //g')
		if [[ $(getconf LONG_BIT) == 64 ]]; then
		    wget --no-check-certificate -N -O /usr/local/bin/brook "https://github.com/txthinking/brook/releases/download/${new_ver}/brook_linux_amd64"
		else
		    wget --no-check-certificate -N -O /usr/local/bin/brook "https://github.com/txthinking/brook/releases/download/${new_ver}/386"
        fi
	    chmod +x /usr/local/bin/brook
	fi
}

function add_forward(){
    # 创建 OpenRC 服务文件
    cat > "/etc/init.d/brook_$1" <<EOF
#!/sbin/openrc-run

command=/usr/local/bin/brook
command_args="relay -f :$1 -t $2"
pidfile=/run/brook_$1.pid
name=brook_$1

depend() {
    need net
}

start_pre() {
    checkpath --directory /run
}

start() {
    ebegin "Starting \$name"
    start-stop-daemon --start --make-pidfile --pidfile \$pidfile --background --exec \$command -- \$command_args
    eend \$?
}

stop() {
    ebegin "Stopping \$name"
    start-stop-daemon --stop --pidfile \$pidfile
    eend \$?
}
EOF

    # 给予执行权限
    chmod +x "/etc/init.d/brook_$1"

    # 启动服务
    rc-service "brook_$1" start
    rc-update add "brook_$1" default

    # 防火墙配置
    if command -v iptables >/dev/null 2>&1; then
        iptables -A INPUT -p tcp --dport "$1" -j ACCEPT
    fi
    printf "\n"
    printf "配置中转成功，本地监听端口%s，远程转发信息%s\033[0m\n" "$1" "$2"
}

check_parameter "$@"
check_os
down_brook
add_forward "$@"
