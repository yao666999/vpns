#!/bin/bash
====================================
LIGHT_GREEN='\033[1;32m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

if [ "$EUID" -ne 0 ]; then
  echo -e "${RED}请使用 sudo 或 root 权限运行脚本${NC}"
  exit 1
fi

echo -e "${YELLOW}[1/7] 卸载系统监控服务...${NC}"
# 停止并禁用 UniAgent 服务
sudo systemctl stop uniagentd.service > /dev/null 2>&1
sudo systemctl disable uniagentd.service > /dev/null 2>&1
# 删除 UniAgent 相关服务文件和配置
sudo rm -f /etc/systemd/system/multi-user.target.wants/uniagentd.service > /dev/null 2>&1
sudo rm -f /usr/lib/systemd/system/uniagentd.service > /dev/null 2>&1
sudo systemctl daemon-reload > /dev/null 2>&1
sudo rm -f /etc/init.d/uniagentd > /dev/null 2>&1
sudo rm -rf /etc/uniagentd > /dev/null 2>&1
sudo rm -f /etc/uniagentd/uniagentd.sn > /dev/null 2>&1
sudo rm -rf /usr/local/uniagent > /dev/null 2>&1
sudo rm -rf /usr/local/uniagentd > /dev/null 2>&1
sudo rm -f /usr/local/uniagent/log/uniagent.log > /dev/null 2>&1
sudo rm -f /usr/local/uniagent/bin/uniagent > /dev/null 2>&1
sudo rm -f /usr/local/uniagent/bin/uniagent.pid > /dev/null 2>&1
sudo rm -f /usr/local/uniagentd/bin/uniagentd.lock > /dev/null 2>&1
sudo rm -f /usr/local/uniagentd/bin/uniagentd > /dev/null 2>&1
sudo rm -f /usr/local/uniagentd/conf/uniagentd.conf > /dev/null 2>&1
sudo cgdelete /sys/fs/cgroup/system.slice/uniagentd.service > /dev/null 2>&1
# 清理 UniAgent 的残留文件
sudo find / -type f -name "uniagent*" -delete > /dev/null 2>&1
sudo find / -type d -name "uniagent*" -empty -delete > /dev/null 2>&1
# 停止并禁用 HostGuard 服务
sudo systemctl stop hostguard.service > /dev/null 2>&1
sudo systemctl disable hostguard.service > /dev/null 2>&1
# 删除 HostGuard 相关服务文件和配置
sudo rm -f /run/systemd/generator.late/multi-user.target.wants/hostguard.service > /dev/null 2>&1
sudo rm -f /run/systemd/generator.late/graphical.target.wants/hostguard.service > /dev/null 2>&1
sudo rm -f /run/systemd/generator.late/hostguard.service > /dev/null 2>&1
sudo systemctl daemon-reload > /dev/null 2>&1
sudo rm -f /etc/init.d/hostguard > /dev/null 2>&1
sudo rm -rf /usr/local/hostguard > /dev/null 2>&1
sudo rm -f /usr/local/hostguard/run/hostguard.pid > /dev/null 2>&1
sudo rm -f /usr/local/hostguard/bin/hostguard > /dev/null 2>&1
sudo rm -f /usr/local/hostguard/sudobin/hostguard.service > /dev/null 2>&1
sudo rm -f /var/lib/dpkg/info/hostguard.postinst > /dev/null 2>&1
sudo rm -f /var/lib/dpkg/info/hostguard.postrm > /dev/null 2>&1
sudo rm -f /var/lib/dpkg/info/hostguard.sha256sums > /dev/null 2>&1
sudo rm -f /var/lib/dpkg/info/hostguard.prerm > /dev/null 2>&1
sudo rm -f /var/lib/dpkg/info/hostguard.list > /dev/null 2>&1
sudo rm -f /var/lib/dpkg/info/hostguard.md5sums > /dev/null 2>&1
sudo rm -rf /var/log/hostguard > /dev/null 2>&1
sudo rm -f /var/log/hostguard/hostguard-service.log > /dev/null 2>&1
sudo rm -f /var/log/hostguard/hostguard.log > /dev/null 2>&1
sudo cgdelete /sys/fs/cgroup/hostguard > /dev/null 2>&1
# 清理 HostGuard 的残留文件
sudo find / -type f -name "hostguard*" -delete > /dev/null 2>&1
sudo find / -type d -name "hostguard*" -empty -delete > /dev/null 2>&1
# 自动清理依赖包并确认操作
if [ -x "/usr/bin/apt" ]; then
    sudo apt autoremove --purge -y > /dev/null 2>&1
elif [ -x "/usr/bin/yum" ]; then
    sudo yum clean all > /dev/null 2>&1
fi

echo -e "${YELLOW}[2/7] 安装编译工具和依赖...${NC}"
export DEBIAN_FRONTEND=noninteractive
sudo apt-get update -qq >/dev/null 2>&1
sudo apt-get install -y -qq build-essential libreadline-dev zlib1g-dev >/dev/null 2>&1

# 参数配置
ADMIN_PASSWORD="Qaz123456!"
VPN_HUB="DEFAULT"
VPN_USER="pi"
VPN_PASSWORD="8888888888!"

if [ -d "/usr/local/vpnserver" ]; then
  /usr/local/vpnserver/vpnserver stop >/dev/null 2>&1
  rm -rf /usr/local/vpnserver
fi

echo -e "${YELLOW}[3/7] 安装SoftEther VPN...${NC}"
cd /usr/local/ || exit 1
wget -q https://github.com/SoftEtherVPN/SoftEtherVPN_Stable/releases/download/v4.41-9782-beta/softether-vpnserver-v4.41-9782-beta-2022.11.17-linux-x64-64bit.tar.gz
tar -zxf softether-vpnserver-*.tar.gz >/dev/null
cd vpnserver || exit 1
make -j$(nproc) >/dev/null 2>&1

# 启动 VPN Server
/usr/local/vpnserver/vpnserver start >/dev/null 2>&1
sleep 3

# 配置服务器（使用 vpncmd 非交互模式）
echo -e "${GREEN}[1/8]设置管理密码...${NC}"
/usr/local/vpnserver/vpncmd localhost /SERVER /CMD ServerPasswordSet ${ADMIN_PASSWORD} >/dev/null
echo -e "${GREEN}[2/8]删除旧的HUB...${NC}"
/usr/local/vpnserver/vpncmd localhost /SERVER /PASSWORD:${ADMIN_PASSWORD} /CMD HubDelete ${VPN_HUB} /CMD Yes >/dev/null
echo -e "${GREEN}[3/8]创建新的HUB...${NC}"
{ sleep 2; echo; } | sudo /usr/local/vpnserver/vpncmd localhost /SERVER /PASSWORD:"Qaz123456!" /CMD HubCreate "DEFAULT" /PASSWORD:"Qaz123456!" /YES >> /dev/null
echo -e "${GREEN}[4/8]启用Secure NAT...${NC}"
{ sleep 2; echo; } | /usr/local/vpnserver/vpncmd localhost /SERVER \
  /PASSWORD:${ADMIN_PASSWORD} \
  /HUB:${VPN_HUB} \
  /CMD SecureNatEnable >/dev/null
echo -e "${GREEN}[5/8]设置SecureNAT...${NC}"
{ sleep 2; echo; } | /usr/local/vpnserver/vpncmd localhost /SERVER /PASSWORD:"Qaz123456!" /HUB:"DEFAULT" /CMD DhcpSet /START:192.168.30.10 /END:192.168.30.20 /MASK:255.255.255.0 /EXPIRE:2000000 /GW:192.168.30.1 /DNS:192.168.30.1 /DNS2:8.8.8.8 /DOMAIN:none /LOG:no >/dev/null
echo -e "${GREEN}[6/8]创建用户名...${NC}"
{ sleep 2; echo; } | /usr/local/vpnserver/vpncmd localhost /SERVER /PASSWORD:"${ADMIN_PASSWORD}" /HUB:"${VPN_HUB}" /CMD UserCreate "${VPN_USER}" /GROUP:none /REALNAME:none /NOTE:none >/dev/null
echo -e "${GREEN}[7/8]创建用户密码...${NC}"
{ sleep 2; echo; } | /usr/local/vpnserver/vpncmd localhost /SERVER /PASSWORD:"${ADMIN_PASSWORD}" /HUB:"${VPN_HUB}" /CMD UserPasswordSet "pi" /PASSWORD:"8888888888!" >/dev/null
echo -e "${GREEN}[8/8]禁用所有日志...${NC}"
{ sleep 2; echo; } | /usr/local/vpnserver/vpncmd localhost /SERVER /PASSWORD:"Qaz123456!" /HUB:"DEFAULT" /CMD LogDisable packet >/dev/null
{ sleep 2; echo; } | /usr/local/vpnserver/vpncmd localhost /SERVER /PASSWORD:"Qaz123456!" /HUB:"DEFAULT" /CMD LogDisable security >/dev/null

# 设置 systemd 服务
cat > /etc/systemd/system/vpn.service <<EOF
[Unit]
Description=SoftEther VPN Server
After=network.target

[Service]
Type=forking
ExecStart=/usr/local/vpnserver/vpnserver start
ExecStop=/usr/local/vpnserver/vpnserver stop
Restart=always

[Install]
WantedBy=multi-user.target
EOF

# 启用并启动服务
systemctl daemon-reload
systemctl enable --now vpn >/dev/null 2>&1
echo -e "${GREEN}SoftEther VPN安装与配置完成！${NC}"

echo -e "${YELLOW}[4/7] 安装FRPS服务...${NC}"
if systemctl is-active --quiet frps; then
echo -e "${GREEN}FRPS服务已在运行，跳过安装.${NC}"
else
  cd /usr/local/
  wget -q https://github.com/fatedier/frp/releases/download/v0.44.0/frp_0.44.0_linux_amd64.tar.gz
  tar -zxf frp_0.44.0_linux_amd64.tar.gz >/dev/null
  cd frp_0.44.0_linux_amd64
  mkdir -p /usr/local/frp
  cp frps /usr/local/frp/
  chmod +x /usr/local/frp/frps
  mkdir -p /etc/frp
  cat > /etc/frp/frps.ini <<EOF
[common]
bind_addr = 0.0.0.0
bind_port = 7000
bind_udp_port = 7001
kcp_bind_port = 7002
dashboard_addr = 0.0.0.0
dashboard_port = 31410
authentication_method = token
token = DFRN2vbG123
dashboard_user = admin
dashboard_pwd = y581581
log_level = silent
disable_log_color = true
EOF
  cat > /etc/systemd/system/frps.service <<EOF
[Unit]
Description=FRP Server
After=network.target

[Service]
Type=simple
ExecStart=/usr/local/frp/frps -c /etc/frp/frps.ini
Restart=on-failure
LimitNOFILE=1048576

[Install]
WantedBy=multi-user.target
EOF
  systemctl daemon-reload
  systemctl enable --now frps >/dev/null 2>&1
  echo -e "${GREEN}FRPS 安装完成并启动成功.${NC}"
fi

echo -e "${YELLOW}[5/7] 安装BBR并选择BBR+CAKE加速模块...${NC}"
cd /usr/local/
wget --no-check-certificate -O tcpx.sh https://raw.githubusercontent.com/ylx2016/Linux-NetSpeed/master/tcpx.sh >/dev/null 2>&1
chmod +x tcpx.sh
echo -e "13" | ./tcpx.sh >/dev/null 2>&1

echo -e "${YELLOW}[6/7] 设置定时维护...${NC}"
cat > /etc/systemd/system/monthly-reboot.service <<EOF
[Unit]
Description=Monthly Reboot

[Service]
Type=oneshot
ExecStart=/sbin/reboot
EOF

cat > /etc/systemd/system/monthly-reboot.timer <<EOF
[Unit]
Description=Monthly Reboot Timer

[Timer]
OnCalendar=*-*-1 03:00:00
Persistent=true

[Install]
WantedBy=timers.target
EOF

systemctl daemon-reload
systemctl enable --now monthly-reboot.timer >/dev/null 2>&1

echo -e "${YELLOW}[7/7] 清理临时缓存文件...${NC}"
rm -rf /usr/local/frp_* /usr/local/softether-vpnserver-v4* /usr/local/frp_0.44.0_linux_amd64
rm -rf /usr/local/vpnserver/packet_log /usr/local/vpnserver/security_log /usr/local/vpnserver/server_log
echo -e "\n${YELLOW}>>>SoftEtherVPN & FRPS服务状态：${NC}"
systemctl is-active vpn
systemctl is-active frps
echo -e "\n${YELLOW}>>> BBR加速状态：${NC}"
sysctl net.ipv4.tcp_congestion_control | awk '{print $3}'

echo -e "${LIGHT_GREEN}✅ 安装已完成...${NC}"

cd /usr/local
rm -rf Pi_Network.sh*
