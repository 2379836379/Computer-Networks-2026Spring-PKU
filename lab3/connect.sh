#!/bin/bash

# 1. 创建两个相连的虚拟以太网设备
# ip link add (端口名称) 接口类型(type veth) (n2)
ip link add n1-eth0 type veth peer name n2-eth0

# 2. 获取容器 n1 的网络命名空间，容器 n1 的进程 PID
ns1=`docker inspect -f '{{.State.Pid}}' n1`
# Docker 默认隐藏命名空间，将命名空间暴露到系统默认可查询的位置
# 容器网络命名空间在内核中的位置 / 系统标准的网络命名空间目录
ln -s /proc/$ns1/ns/net /var/run/netns/$ns1

# 3. 将 n1-eth0 移动到 n1 的命名空间(nets $ns1)
ip link set n1-eth0 netns $ns1

# 4. 在 n1 命名空间中配置网络
# 在容器 n1 中启动（激活）n1-eth0 网卡
ip netns exec $ns1 ip link set n1-eth0 up
# 给容器 n1 的 n1-eth0 网卡配置 IP 地址 10.0.0.1/24
ip netns exec $ns1 ip addr add 10.0.0.1/24 dev n1-eth0

# 5. 获取容器 n2 的网络命名空间
ns2=`docker inspect -f '{{.State.Pid}}' n2`
ln -s /proc/$ns2/ns/net /var/run/netns/$ns2

# 6. 将 n2-eth0 移动到 n2 的命名空间
ip link set n2-eth0 netns $ns2

# 7. 在 n2 命名空间中配置网络
ip netns exec $ns2 ip link set n2-eth0 up
ip netns exec $ns2 ip addr add 10.0.0.2/24 dev n2-eth0
# 在容器 n1 中向容器 n2 发送 3 个 ping 包
ip netns exec $ns1 ping -c 3 10.0.0.2