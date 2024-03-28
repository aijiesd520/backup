#!/bin/bash
claer
echo "要打印的文字或变量"
RED_COLOR='\e[1;31m'
GREEN_COLOR='\e[1;32m'
YELLOW_COLOR='\e[1;33m'
BLUE_COLOR='\e[1;34m'
PINK_COLOR='\e[1;35m'
SHAN='\e[1;33;5m'
RES='\e[0m'

NOTE='

              MailBox - www.cooluc.com

                CentOS 7 & Redhat 7

---------------------------------------------------------
            __  ___      _ ______
           /  |/  /___ _(_) / __ )____  _  __
          / /|_/ / __ `/ / / __  / __ \| |/_/
         / /  / / /_/ / / / /_/ / /_/ />  <
        /_/  /_/\__,_/_/_/_____/\____/_/|_|

---------------------------------------------------------
';
echo -e "${GREEN_COLOR}$NOTE${RES}\r\n"

# Check uid
if [ "$(id -u)" != "0" ]; then
    echo -e "\r\n${RED_COLOR}Error: root user is required to run install.${RES}\r\n" 1>&2
    exit 0;
else
	sed -i 's/SELINUX=enforcing/SELINUX=disabled/g' /etc/selinux/config
    setenforce 0
    platform=`arch`;
fi

# Check Ports
check_port() {
    echo -en "\r\nCheck the system ports ..."
    if ! command -v netstat >/dev/null 2>&1; then
        yum install -y net-tools > /dev/null 2>&1
    elif ! command -v nmap >/dev/null 2>&1; then
        yum install -y nmap > /dev/null 2>&1
    else
        sleep 2
    fi

    if netstat -lnp|grep 3306 >/dev/null 2>&1; then
        echo -e "\r${RED_COLOR}安装终止：MySQL 3306 端口被占用，请使用全新系统安装${RES}\r\n"
        exit 1;
    elif netstat -lnp|grep 8010 >/dev/null 2>&1; then
        echo -e "\r${RED_COLOR}安装终止：nginx 8010 端口被占用，请使用全新系统安装${RES}\r\n"
        exit 1;
    elif netstat -lnp|grep 8000 >/dev/null 2>&1; then
        echo -e "\r${RED_COLOR}安装终止：nginx 8000 端口被占用，请使用全新系统安装${RES}\r\n"
        exit 1;
    fi
    SMTP_STATE=$(nmap smtp.163.com -p 25 | grep open | wc -l)
    if [ $SMTP_STATE -ne 1 ]; then
        echo -e "\r ${RED_COLOR}注意：本机 25 端口受阻，邮箱将无法正常对外收发邮件！${RES}\r\n"
        echo -e " ${YELLOW_COLOR}你可以键入${RES} ${BLUE_COLOR}Ctrl C${RES} ${YELLOW_COLOR}组合按钮终止安装${RES}"
        echo -ne "\r\n ${SHAN}如需继续安装，请按回车${RES}"
        read
    else
        echo -e "    [ ${GREEN_COLOR}OK${RES} ]"
    fi
}

domain() {
    echo -e "\r\n设置域名，格式: ${GREEN_COLOR}example.com${RES}"
    echo -n "请输入主域名："
    read mydomain
    if [ -z $mydomain ];then
        echo -e "\r\n${RED_COLOR}域名不能为空，安装终止${RES}\r\n";
        exit 1;
    else
        if [[ "$mydomain" =~ "baidu.com" ]]||[[ "$mydomain" =~ "qq.com" ]]||[[ "$mydomain" =~ "gmail.com" ]]||[[ "$mydomain" =~ "163.com" ]]||[[ "$mydomain" =~ "yahoo.com" ]]||[[ "$mydomain" =~ "sina.com" ]]||[[ "$mydomain" =~ "sina.cn" ]]||[[ "$mydomain" =~ "icloud.com" ]]||[[ "$mydomain" =~ "88.com" ]]||[[ "$mydomain" =~ "139.com" ]]||[[ "$mydomain" =~ "189.com" ]]||[[ "$mydomain" =~ "aliyun.com" ]]||[[ "$mydomain" =~ "sohu.com" ]]||[[ "$mydomain" =~ "263.net" ]]||[[ "$mydomain" =~ "xinnet.com" ]]||[[ "$mydomain" =~ "outlook.com" ]]||[[ "$mydomain" =~ "zoho.com" ]];then
            echo -e "\r\n${RED_COLOR}域名不合法，安装终止${RES}\r\n";
            exit 1;
        fi
        # 生成 MySQL 15位随机密码
        mysqlpassword=$(cat /proc/sys/kernel/random/uuid|md5sum|base64|awk '{print substr($0, 20, 15)}');
        # 内部通讯
        if [ `grep -c "mail.$mydomain" /etc/hosts` -eq '0' ];then
            echo "127.0.0.1   $mydomain mail.$mydomain imap.$mydomain smtp.$mydomain" >> /etc/hosts
        fi
    fi
}

# Install Core packages
install_rpm() {
    echo -e "\r\n${GREEN_COLOR}Install the Core packages ...${RES}\r\n"
    sleep 2
    # repos
    if [[ $os_release == "centos" ]];then
        # CentOS Linux 7 (Core)
        yum install -y epel-release
    elif [[ $os_release == "redhat" ]];then
        # RedHat Enterprise Linux Server
        yum install -y https://mirrors.tuna.tsinghua.edu.cn/epel/epel-release-latest-7.noarch.rpm
    fi
    if [ $isCN = "CN" ];then
        # tsinghua epel source (el7)
        cat > /etc/yum.repos.d/epel.repo <<"EOF"
[epel]
name=Extra Packages for Enterprise Linux $releasever - $basearch
baseurl=http://mirrors.tuna.tsinghua.edu.cn/epel/$releasever/$basearch
failovermethod=priority
enabled=1
gpgcheck=0
gpgkey=file:///etc/pki/rpm-gpg/RPM-GPG-KEY-EPEL-7

[epel-debuginfo]
name=Extra Packages for Enterprise Linux $releasever - $basearch - Debug
baseurl=http://mirrors.tuna.tsinghua.edu.cn/epel/$releasever/$basearch/debug
failovermethod=priority
enabled=0
gpgkey=file:///etc/pki/rpm-gpg/RPM-GPG-KEY-EPEL-7
gpgcheck=0

[epel-source]
name=Extra Packages for Enterprise Linux $releasever - $basearch - Source
baseurl=http://mirrors.tuna.tsinghua.edu.cn/epel/$releasever/SRPMS
failovermethod=priority
enabled=0
gpgkey=file:///etc/pki/rpm-gpg/RPM-GPG-KEY-EPEL-7
gpgcheck=0
EOF
    fi

    # Add repository
    if ! command -v yum-config-manager >/dev/null 2>&1; then
        yum install -y yum-utils
    fi
    rpm --import https://repo.cooluc.com/MAILBOX-REPO-GPG
    yum-config-manager --add-repo https://repo.cooluc.com/mailbox.repo

    # Remove packages
    yum remove -y sendmail postfix* dovecot*

    # Init yum cache
    yum clean all
    yum makecache

    # Install core packages
    yum install -y postfix3 postfix3-ldap postfix3-mysql pypolicyd-spf perl-DBI perl-JSON-XS perl-NetAddr-IP perl-Mail-SPF perl-Sys-Hostname-Long libtool-ltdl fail2ban fail2ban-server fail2ban-sendmail fail2ban-firewalld iptables iptables-services
    yum install -y dovecot dovecot-mysql dovecot-devel dovecot-pgsql dovecot-pigeonhole
    yum install -y clamav clamav-server clamav-filesystem clamav-lib clamav-update
    # amavis
    if [ "$platform" == "aarch64" ];then
        yum install -y amavisd-new
    else
        yum install -y amavis
    fi
}

config_file() {
    echo -e "\r\n${GREEN_COLOR}Create postfix,dovecot,amavisd configuration files ...${RES}\r\n"
    sleep 2
    if [ ! -d "/etc/tmpfiles.d" ]; then
        mkdir -p /etc/tmpfiles.d
        echo "d /var/run/clamd.amavisd 0755 amavis amavis -" > /etc/tmpfiles.d/clamd.amavisd.conf
    else
        echo "d /var/run/clamd.amavisd 0755 amavis amavis -" > /etc/tmpfiles.d/clamd.amavisd.conf
    fi

    # spamassassin - drop AHBL DNSbl
    sed -i 's/^[^#].*DNS_FROM_AHBL_RHSBL*/# &/g' /usr/share/spamassassin/20_dnsbl_tests.cf

    # amavisd config & systemd
    cat >/etc/sysconfig/clamd.amavisd <<EOF
CLAMD_CONFIGFILE=/etc/clamd.d/amavisd.conf
CLAMD_SOCKET=/var/run/clamd.amavisd/clamd.sock
EOF
    cat >/usr/lib/systemd/system/clamd\@.service <<EOF
[Unit]
Description = clamd scanner (%i) daemon
After = syslog.target nss-lookup.target network.target

[Service]
Type = simple
ExecStart = /usr/sbin/clamd -c /etc/clamd.d/%i.conf --foreground=yes
Restart = on-failure
PrivateTmp = true

[Install]
WantedBy=multi-user.target
EOF
    systemctl daemon-reload

    # fail2ban config
    cat >/etc/fail2ban/jail.local <<EOF
#
# mailbox
#
[ssh]
enabled     = false
filter      = sshd
action      = iptables[name=ssh, port="ssh", protocol=tcp]
logpath     = /var/log/secure
maxretry    = 5
bantime     = 36000
findtime  	= 3600
ignoreip    = 127.0.0.1 127.0.0.0/8 10.0.0.0/8 172.16.0.0/12 192.168.0.0/16

[dovecot]
enabled     = true
filter      = dovecot
action      = iptables-multiport[name=dovecot, port="smtp,pop3,pop3s,imap,imaps", protocol=tcp]
logpath     = /var/log/dovecot.log
maxretry    = 5
bantime     = 3600
findtime  	= 3600
ignoreip    = 127.0.0.1 127.0.0.0/8 10.0.0.0/8 172.16.0.0/12 192.168.0.0/16

[postfix]
enabled     = true
filter      = postfix.mailbox
action      = iptables-multiport[name=postfix, port="http,https,smtp,submission,pop3,pop3s,imap,imaps,sieve", protocol=tcp]
logpath     = /var/log/maillog
maxretry    = 5
bantime     = 36000
findtime  	= 3600
ignoreip    = 127.0.0.1 127.0.0.0/8 10.0.0.0/8 172.16.0.0/12 192.168.0.0/16
EOF
    cat >/etc/fail2ban/filter.d/postfix.mailbox.conf <<EOF
#
# mailbox
#
[Definition]
failregex = \[<HOST>\]: SASL (PLAIN|LOGIN) authentication failed
            reject: RCPT from (.*)\[<HOST>\]: 550 5.1.1
            reject: RCPT from (.*)\[<HOST>\]: 450 4.7.1
            reject: RCPT from (.*)\[<HOST>\]: 554 5.7.1
ignoreregex =
EOF
    rm -rf /etc/dovecot /etc/postfix /etc/amavisd
    cp -rf install/etc/dovecot /etc/ && cp -rf install/etc/postfix /etc/ && cp -rf install/etc/amavisd /etc/
    ln -sf /etc/amavisd/amavisd.conf /etc/amavisd.conf
    sed -i 's/^#Example/Example/' /etc/clamd.d/scan.conf
    # sed -i "s/cooluc.com/$mydomain/g" `grep "cooluc" -rl /etc/dovecot`
    sed -i "s/cooluc.com/$mydomain/g" `grep "cooluc" -rl /etc/postfix`
    sed -i "s/cooluc.com/$mydomain/g" `grep "cooluc" -rl /etc/amavisd`
    sed -i "s/DEFMYSQLPASSWORD/$mysqlpassword/g" `grep "DEFMYSQLPASSWORD" -rl /etc/dovecot`
    sed -i "s/DEFMYSQLPASSWORD/$mysqlpassword/g" `grep "DEFMYSQLPASSWORD" -rl /etc/postfix`
}

install_mailbox() {
    echo -e "\r\n${GREEN_COLOR}Install the MailBox Web panel and Database ...${RES}\r\n"
    sleep 2
    cp -rf install/mailbox /
    \cp install/mailbox.sql /mailbox/mailbox.sql
    sed -i "s/cooluc.com/$mydomain/g" /mailbox/mailbox.sql
    current_time=`date "+%Y-%m-%d %H:%M:%S"`
    sed -i "s/DATE-CODE/$current_time/g" /mailbox/mailbox.sql
    mysql -umailbox -p$mysqlpassword mailbox < /mailbox/mailbox.sql
    cat > /mailbox/www/rainloop/data/_data_/_default_/domains/$mydomain.ini <<EOF
imap_host = "imap.$mydomain"
imap_port = 143
imap_secure = "None"
imap_short_login = Off
sieve_use = Off
sieve_allow_raw = Off
sieve_host = ""
sieve_port = 4190
sieve_secure = "None"
smtp_host = "smtp.$mydomain"
smtp_port = 25
smtp_secure = "None"
smtp_short_login = Off
smtp_auth = On
smtp_php_mail = Off
white_list = ""
EOF
    cat > /mailbox/www/admin/core/config.php <<EOF
<?php
//配置文件
return [
    'dbhost' => '127.0.0.1',//数据库连接地址
    'dbuser' => 'mailbox',//数据库账号
    'dbpw' => '$mysqlpassword',//数据库密码
    'dbname' => 'mailbox',//数据库名称
    'dbcharset' => 'utf8',//数据库编码
    'dbprefix'=> 'i_',//数据库表的前缀
    'code_key' => '`echo $mydomain|base64`',//加密钥匙
    'url' => 'http://mail.$mydomain:8010',//邮箱后台管理地址（后面不带 / 线）
    'webmail_url' => 'http://mail.$mydomain:8000',//网页邮箱地址（后面不带 / 线）
    'maildir'=>'/mailbox/mail',//邮件存放目录，请不要修改
    'home_default' =>'Center',//默认项目
    'home_allow' => ['Center','Api'],//允许项目
    'module_default' =>'Index',//默认模块
    'action_default' =>'index',//默认控制器
    'prefix'=>'mailbox_',//网站通用前缀，包括session,cookie

];

EOF
    # 判断 vmail 用户&用户组，不存在则添加
    egrep "^vmail" /etc/group >& /dev/null
    if [ $? -ne 0 ];then
        groupadd vmail
    fi
    egrep "^vmail" /etc/passwd >& /dev/null
    if [ $? -ne 0 ];then
        useradd vmail -g vmail -s /sbin/nologin -M
    fi
    amavisd genrsa /mailbox/dkim/mail.pem 2048
    # amavisd genrsa /mailbox/dkim/mail.pem # 1024
    chown -R amavis.amavis /mailbox/dkim/
    chown -R vmail.vmail /mailbox/mail/
    echo
    echo -e "创建 ${GREEN_COLOR}*.$mydomain${RES} 域名证书（非授信） ..."
    sleep 2
    cat > /mailbox/ssl/dovecot-openssl.cnf <<EOF
[ req ]
default_bits = 4096
encrypt_key = yes
distinguished_name = req_dn
x509_extensions = cert_type
prompt = no

[ req_dn ]
# country (2 letter code)
#C=FI

# State or Province Name (full name)
#ST=

# Locality Name (eg. city)
#L=Helsinki

# Organization (eg. company)
#O=Dovecot

# Organizational Unit Name (eg. section)
OU=IMAP server

# Common Name (*.example.com is also possible)
CN=*.$mydomain

# E-mail contact
emailAddress=admin@$mydomain

[ cert_type ]
nsCertType = server

EOF
    CERTFILE=/mailbox/ssl/dovecot/certs.crt
    KEYFILE=/mailbox/ssl/dovecot/private.key
    OPENSSLCONFIG=/mailbox/ssl/dovecot-openssl.cnf
    openssl req -new -x509 -nodes -config $OPENSSLCONFIG -out $CERTFILE -keyout $KEYFILE -days 3650
    chmod 0600 $KEYFILE
    openssl x509 -subject -fingerprint -noout -in $CERTFILE
    \cp /mailbox/ssl/dovecot/certs.crt /mailbox/ssl/postfix/certs.crt
    \cp /mailbox/ssl/dovecot/private.key /mailbox/ssl/postfix/private.key
    echo
    sleep 2
}

install_spf() {
    \cp install/perl/10_chinese_rules.cf /usr/share/spamassassin/
    \cp install/perl/postfix-policyd-spf-perl /usr/libexec/postfix/
    chmod -R 0755 /usr/libexec/postfix/postfix-policyd-spf-perl
}

install_nginx() {
    echo -e "\r\n${GREEN_COLOR}Install nginx-1.22.0 dependent packages ...${RES}\r\n"
    sleep 2

    # 判断 nginx 用户&用户组，不存在则添加
    egrep "^nginx" /etc/group >& /dev/null
    if [ $? -ne 0 ];then
        groupadd nginx
    fi
    egrep "^nginx" /etc/passwd >& /dev/null
    if [ $? -ne 0 ];then
        useradd nginx -g nginx -s /sbin/nologin -M
    fi
    chown -R nginx.nginx /mailbox/www
    yum remove -y gd
    yum install -y gd-last openssl11 pcre zlib
    tar -Jxf install/nginx.tar.xz -C /mailbox/
    chown -R root.root /mailbox/nginx
    \cp /mailbox/nginx/nginx.service /usr/lib/systemd/system/nginx\@mailbox.service
    systemctl daemon-reload
}

install_php() {
    echo -e "\r\n${GREEN_COLOR}Install php-7.4.24 dependent packages ...${RES}\r\n"
    sleep 2
    yum install -y libc-client libtidy postgresql-libs enchant libicu oniguruma net-snmp-libs libsodium libxslt ImageMagick gd-last libzip5 openssl11
    tar -Jxf install/php.tar.xz -C /mailbox/
    chown -R root.root /mailbox/php
    \cp /mailbox/php/php-fpm.service /usr/lib/systemd/system/php-fpm\@mailbox.service
    systemctl daemon-reload
}

install_mariadb() {
    echo -e "\r\n${GREEN_COLOR}Install MariaDB ...${RES}\r\n"
    sleep 2
    if [ -f "/usr/bin/mysql" ];then
        echo -e "\r\n${RED_COLOR}系统已经安装 MySQL 数据库，防止数据库冲突，请使用全新系统进行安装！${RES}\r\n"
        exit 0;
    elif [ -d "/var/lib/mysql" ]; then
        echo -e "An old MySQL database directory has been detected in the system and is move to \033[32m/var/lib/mysql.backup\033[0m.\r\n"
        mv /var/lib/mysql /var/lib/mysql.backup
    fi
    yum install mariadb-server mariadb -y
    echo -e "\r\n${GREEN_COLOR}Starting MariaDB ...${RES}\r\n"
    systemctl start mariadb
    if ! netstat -lnp|grep 3306 >/dev/null 2>&1;then
        echo -e "\r\n${RED_COLOR}The MariaDB failed to startup and the installation was terminated. Please try again with a brand new CentOS 7 or RedHat 7 system.${RES}\r\n"
        exit 0;
    fi
    echo -e "${GREEN_COLOR}Create MariaDB mailbox user/database ...${RES}\r\n"
    mysql -uroot <<EOF
create user 'mailbox'@'localhost' identified by '$mysqlpassword';
flush privileges;
create database mailbox DEFAULT CHARSET utf8 COLLATE utf8_general_ci;
grant all privileges on mailbox.* to mailbox@localhost identified by '$mysqlpassword';
flush privileges;
show databases;
EOF
}

check_install() {
    if ! rpm -qa | grep postfix3 > /dev/null;then
        echo "postfix Installation failed"
        echo -e "${RED_COLOR}错误：postfix 安装失败，请检查是否使用全新 CentOS 7 或 RedHat 7 系统安装。${RES}"
        exit 1
    elif ! rpm -qa | grep dovecot > /dev/null;then
        echo "dovecot Installation failed"
        echo -e "${RED_COLOR}错误：dovecot 安装失败，请检查是否使用全新 CentOS 7 或 RedHat 7 系统安装。${RES}"
        exit 1
    elif ! rpm -qa | grep clamav > /dev/null;then
        echo "clamav Installation failed"
        echo -e "${RED_COLOR}错误：clamav 安装失败，请检查是否使用全新 CentOS 7 或 RedHat 7 系统安装。${RES}"
        exit 1
    elif ! rpm -qa | grep spamassassin > /dev/null;then
        echo "spamassassin Installation failed"
        echo -e "${RED_COLOR}错误：spamassassin 安装失败，请检查是否使用全新 CentOS 7 或 RedHat 7 系统安装。${RES}"
        exit 1
    fi
    if [ "$platform" == "aarch64" ];then
        if ! rpm -qa | grep amavisd-new > /dev/null;then
            echo "amavisd-new(aarch64) Installation failed"
            echo -e "${RED_COLOR}错误：amavisd-new(aarch64) 安装失败，请检查是否使用全新 CentOS 7 或 RedHat 7 系统安装。${RES}"
            exit 1
        fi
    else
        if ! rpm -qa | grep amavis > /dev/null;then
            echo "amavis Installation failed"
            echo -e "${RED_COLOR}错误：amavis 安装失败，请检查是否使用全新 CentOS 7 或 RedHat 7 系统安装。${RES}"
            exit 1
        fi
    fi
}

configure_iptables() {
    echo -e "\r\n${GREEN_COLOR}Configure iptables ...${RES}\r\n"
    sleep 2
    systemctl mask firewalld > /dev/null 2>&1
    systemctl stop firewalld > /dev/null 2>&1
    systemctl start iptables
    iptables -P INPUT ACCEPT
    iptables -F
    iptables -I INPUT -p tcp --dport 109 -j ACCEPT
    iptables -I INPUT -p tcp --dport 110 -j ACCEPT
    iptables -I INPUT -p tcp --dport 143 -j ACCEPT
    iptables -I INPUT -p tcp --dport 22 -j ACCEPT
    iptables -I INPUT -p tcp --dport 25 -j ACCEPT
    iptables -I INPUT -p tcp --dport 443 -j ACCEPT
    iptables -I INPUT -p tcp --dport 465 -j ACCEPT
    iptables -I INPUT -p tcp --dport 587 -j ACCEPT
    iptables -I INPUT -p tcp --dport 80 -j ACCEPT
    iptables -I INPUT -p tcp --dport 8000 -j ACCEPT
    iptables -I INPUT -p tcp --dport 8010 -j ACCEPT
    iptables -I INPUT -p tcp --dport 993 -j ACCEPT
    iptables -I INPUT -p tcp --dport 995 -j ACCEPT
    service iptables save
}

create_swap() {
if [ `free | awk '/Swap/{print $2}'` == 0 ]; then
    echo -e "\r\n${GREEN_COLOR}Create swap space /mnt/mailbox.swap (2GB) ...${RES}\r\n"
    mkdir -p /mnt/
    dd if=/dev/zero of=/mnt/mailbox.swap bs=1M count=2048
    chmod 0600 /mnt/mailbox.swap
    mkswap /mnt/mailbox.swap
    swapon /mnt/mailbox.swap
    if ! cat /etc/fstab | grep mailbox.swap >/dev/null 2>&1; then
        echo '/mnt/mailbox.swap swap swap defaults 0 0' >>/etc/fstab
    fi
else
    echo -e "\r\n${GREEN_COLOR}Swap space exists, skip create.${RES}\r\n"
fi
}

start_service() {
    echo -e "${GREEN_COLOR}Starting Services ...${RES}\r\n"
    sleep 2
    hostnamectl set-hostname mail.$mydomain
    hostname mail.$mydomain
    systemctl restart spamassassin postfix dovecot fail2ban php-fpm@mailbox nginx@mailbox
    echo -e "${GREEN_COLOR}Enabling Services ...${RES}\r\n"
    systemctl enable postfix dovecot amavisd spamassassin fail2ban clamd@amavisd mariadb iptables php-fpm@mailbox nginx@mailbox >/dev/null 2>&1
    # check port
    if netstat -lnp|grep :25 >/dev/null 2>&1;then
        echo -e "${GREEN_COLOR}Postfix is running ...${RES}\r\n"
    else
        echo -e "${RED_COLOR}错误：Postfix 服务启动失败，请检查是否使用全新 CentOS 7 或 RedHat 7 系统安装。${RES}"
        exit 1;
    fi
    if netstat -lnp|grep :143 >/dev/null 2>&1;then
        echo -e "${GREEN_COLOR}Dovecot is running ...${RES}\r\n"
    else
        echo -e "${RED_COLOR}错误：Dovecot 服务启动失败，请检查是否使用全新 CentOS 7 或 RedHat 7 系统安装。${RES}"
        exit 1;
    fi
    if netstat -lnp|grep :8000 >/dev/null 2>&1 && netstat -lnp|grep :8010 >/dev/null 2>&1;then
        echo -e "${GREEN_COLOR}Web is running ...${RES}\r\n"
    else
        echo -e "${RED_COLOR}错误：Web 服务启动失败，请检查是否使用全新 CentOS 7 或 RedHat 7 系统安装。${RES}"
        exit 1;
    fi
    echo -e "${GREEN_COLOR}Cleaning install files ...${RES}"
    rm -rf install /mailbox/mailbox.sql
    clear
	echo -e "${GREEN_COLOR}$NOTE${RES}"
    echo -e "邮箱域名解析相关教程，请前往 ${GREEN_COLOR}https://www.cooluc.com/${RES} 查阅相关文章！\r\n"
    echo -e "Web邮箱登录：${GREEN_COLOR}http://mail.$mydomain:8000/ ${RES}\r\n"
    echo -e "管理员后台：${GREEN_COLOR}http://mail.$mydomain:8010/ ${RES}"
    echo -e "管理员默认账户：${GREEN_COLOR}admin\033[0m"
    echo -e "管理员默认密码: ${GREEN_COLOR}www.cooluc.com${RES}\r\n"
    echo -e "Postfix & Dovecot 证书目录：${GREEN_COLOR}/mailbox/ssl${RES}"
    cat >/mailbox/default_info.txt <<EOF
======= 域名信息 =======
安装域名：$mydomain

======= 登录信息 =======
用户名：admin
默认密码：www.cooluc.com

====== 数据库信息 ======
数据库名称：mailbox
数据库账号：mailbox
数据库密码：$mysqlpassword
EOF
    # Download ClamAV database
    echo -e "\r\n${GREEN_COLOR}Updating ClamAV database ...${RES}\r\n"
    # freshclam
    rm -f /var/lib/clamav/*
    if [ "$isCN" = "CN" ]; then
    	echo -e "${GREEN_COLOR}Downloading main.cvd ...${RES}"
    	curl -kL https://repo.cooluc.com/source/VirusDatabase/main.cvd -o /var/lib/clamav/main.cvd $CURL_BAR
    	echo -e "${GREEN_COLOR}Downloading daily.cvd ...${RES}"
    	curl -kL https://repo.cooluc.com/source/VirusDatabase/daily.cvd -o /var/lib/clamav/daily.cvd $CURL_BAR
    	echo -e "${GREEN_COLOR}Downloading bytecode.cvd ...${RES}"
    	curl -kL https://repo.cooluc.com/source/VirusDatabase/bytecode.cvd -o /var/lib/clamav/bytecode.cvd $CURL_BAR
    else
    	echo -e "${GREEN_COLOR}Please waiting ...${RES}"
    	freshclam
    fi
    echo -e "\r\n${GREEN_COLOR}Restarting ClamAV Service ...${RES}\r\n"
    chown -R clamupdate:clamupdate /var/lib/clamav
    systemctl restart amavisd clamd@amavisd
    echo -e "${GREEN_COLOR}Successful.${RES}"
}

download_source() {
    echo -e "\r\n${GREEN_COLOR}Downloading MailBox Configure ...${RES}\r\n"
    sleep 2
    curl -kL https://repo.cooluc.com/source/mailbox.tar.xz -o mailbox.tar.xz $CURL_BAR
    if [ $? -ne 0 ]; then
        echo -e "${RED_COLOR}错误：MailBox 安装文件下载失败，请检查网络后重试${RES}"
        exit 1
    else
        rm -rf install
        tar -Jxf mailbox.tar.xz && rm -f mailbox.tar.xz
        pushd install >/dev/null 2>&1
            echo -e "\r\n${GREEN_COLOR}Downloading Prebuilt PHP ...${RES}\r\n"
            curl -kL https://repo.cooluc.com/source/$platform/php.tar.xz -o php.tar.xz $CURL_BAR
            echo -e "\r\n${GREEN_COLOR}Downloading Prebuilt Nginx ...${RES}\r\n"
            curl -kL https://repo.cooluc.com/source/$platform/nginx.tar.xz -o nginx.tar.xz $CURL_BAR
        popd >/dev/null 2>&1
    fi
}

uninstall() {
    echo -en "\r\n${YELLOW_COLOR}注意！该操作不可逆！是否卸载MailBox？${RES}[yes/no]: "
    read input
    if [[ $input == "yes" ]];then
        echo -e "\r\n${RED_COLOR}正在卸载 MailBox ...${RES}\r\n"
        sleep 2
    else
        exit 0
    fi
    echo -e "${GREEN_COLOR}Stopping MailBox Services ...${RES}"
    systemctl stop postfix dovecot amavisd spamassassin fail2ban clamd@amavisd nginx@mailbox php-fpm@mailbox > /dev/null 2>&1
    systemctl disable postfix dovecot amavisd spamassassin fail2ban clamd@amavisd mariadb php-fpm@mailbox nginx@mailbox > /dev/null 2>&1
    echo -e "${GREEN_COLOR}Uninstalling packages ...${RES}"
    yum remove -y postfix* fail2ban fail2ban-server fail2ban-sendmail fail2ban-firewalld dovecot* amavis clamav clamav-server clamav-filesystem clamav-lib clamav-update spamassassin > /dev/null 2>&1
    echo -e "${GREEN_COLOR}Cleaning old files ...${RES}"
    sleep 1
    rm -rf /mailbox /etc/amavisd /etc/dovecot /etc/fail2ban /etc/postfix /etc/amavisd.conf /usr/libexec/postfix/postfix-policyd-spf-perl /etc/clamd.d /usr/lib/systemd/system/nginx\@mailbox.service /usr/lib/systemd/system/php-fpm\@mailbox.service /etc/sysconfig/clamd.amavisd /usr/lib/systemd/system/clamd\@.service /var/lib/clamav/* /usr/share/spamassassin
    rm -rf install
    sed -i '/imap/d' /etc/hosts
    echo -en "\r\n${YELLOW_COLOR}是否卸载数据库，并清理 /var/lib/mysql 数据库存储目录？${RES}[yes/no]: "
    read input
    if [[ $input == "yes" ]];then
        echo
        echo -e "${GREEN_COLOR}Stopping MariaDB Services ...${RES}"
        systemctl stop mariadb > /dev/null 2>&1
        echo -e "${GREEN_COLOR}Uninstalling MariaDB ...${RES}"
        yum remove -y mariadb-server mariadb > /dev/null 2>&1
        rm -rf /var/lib/mysql
    else
        echo -e "${GREEN_COLOR}已跳过数据库卸载。${RES}"
        echo "如需卸载数据库，请手动执行以下命令："
        echo -e "${GREEN_COLOR} yum remove -y mariadb-server mariadb && rm -rf /var/lib/mysql${RES}"
    fi
    echo -e "\r\n${GREEN_COLOR}MailBox 已经在系统中移除.${RES}\r\n"
    exit 0;
}

# check System version
osversion=`cat /etc/redhat-release|sed -r 's/.* ([0-9]+)\..*/\1/'`
if [ $osversion != 7 ]; then
    echo -e "\r\n${RED_COLOR}Error: Please replace the CentOS7 or RedHat7 system install.${RES}\r\n"
    exit 0;
fi

# GetIP
ip_info=`curl -s https://ip.cooluc.com`;
isCN=`echo $ip_info | grep -Po 'country_code\":"\K[^"]+'`;

# Curl progress bar
if curl --help | grep progress-bar >/dev/null 2>&1; then # --progress-bar
    CURL_BAR="--progress-bar";
fi

# Release
release=`cat /etc/os-release | grep PRETTY_NAME`
if [[ $release =~ "RedHat" ]];then
    os_release=redhat
elif [[ $release =~ "CentOS" ]];then
    os_release=centos
fi

# Task menu
echo
echo " 请选择:"
echo
echo -e " ${GREEN_COLOR}1${RES} - 安装 MailBox 邮箱系统" 
echo -e " ${GREEN_COLOR}2${RES} - 卸载"
echo
echo -e " ${GREEN_COLOR}x${RES} - 退出"
echo
echo -n "请输入选择: "
read mode
case $mode in
x|[1]|[1-2]) ;;
*) echo -e '\n ...输入错误.';exit 1;;
esac
if [ -z $mode ]
    then
    echo -e '\n ...输入错误.';exit 1;
else
    if [[ $mode == "1" ]];then
        check_port
        domain
        download_source
        install_mariadb
        install_rpm
        config_file
        configure_iptables
        install_mailbox
        install_nginx
        install_php
        install_spf
        check_install
        create_swap
        start_service
        exit 0;
    elif [[ $mode == "2" ]];then
        uninstall
        exit 0;
    fi
fi
