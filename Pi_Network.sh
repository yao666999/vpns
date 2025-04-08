#!/bin/bash
====================================
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

if [ "$EUID" -ne 0 ]; then
  echo -e "${RED}请使用 sudo 或 root 权限运行脚本${NC}"
  exit 1
fi

echo -e "${YELLOW}[1/7] 卸载系统监控服务...${NC}"
systemctl stop hostguard.service >/dev/null 2>&1
systemctl disable hostguard.service >/dev/null 2>&1
pkill -9 hostguard >/dev/null 2>&1
rm -rf /usr/local/uniagent /usr/local/hostguard /usr/local/uniag >/dev/null 2>&1

echo -e "${YELLOW}[2/7] 安装编译工具和依赖...${NC}"
export DEBIAN_FRONTEND=noninteractive
sudo apt-get update -qq >/dev/null 2>&1
sudo apt-get install -y -qq build-essential libreadline-dev zlib1g-dev >/dev/null 2>&1


echo -e "${GREEN} 检查并卸载现有的 SoftEther VPN...${NC}"
if [ -d "/usr/local/vpnserver" ]; then
  /usr/local/vpnserver/vpnserver stop >/dev/null 2>&1
  rm -rf /usr/local/vpnserver
fi


echo -e "${YELLOW}[3/7] 安装SoftEther VPN ...${NC}"
# 安装目录准备
cd /usr/local/ || exit 1
wget -q https://github.com/SoftEtherVPN/SoftEtherVPN_Stable/releases/download/v4.41-9782-beta/softether-vpnserver-v4.41-9782-beta-2022.11.17-linux-x64-64bit.tar.gz
tar -zxf softether-vpnserver-*.tar.gz >/dev/null
cd vpnserver || exit 1
make -j$(nproc) >/dev/null 2>&1
./vpnserver start >/dev/null 2>&1
sleep 3

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


echo -e "${YELLOW}[4/7] 安装FRPS服务...${NC}"
if systemctl is-active --quiet frps; then
  echo -e "${GREEN}FRPS 服务已在运行，跳过安装.${NC}"
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

echo -e "${YELLOW}[6/7] 设置每月1号自动重启...${NC}"
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

echo -e "\n${YELLOW}>>>SoftEther VPN & FRPS 服务状态：${NC}"
systemctl is-active vpn
systemctl is-active frps

echo -e "\n${YELLOW}>>> BBR 状态：${NC}"
sysctl net.ipv4.tcp_congestion_control | awk '{print $3}'

echo -e "\n${GREEN}✅ 安装已完成...${NC}"
