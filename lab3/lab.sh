#!/bin/bash

source topo.conf

function create_image()
{
	echo 'create_image()'
	echo create image node
	##########################################
	# your code here 
	##########################################
	docker image build -t node .
}

function create_nodes()
{
	echo 'create_nodes()'
	##########################################
	# your code here 
	##########################################
	for h in ${nodes[@]}; do
	# 避免Docker自带网络 
		docker container create --network none --privileged --name $h node
	done
}


function run_nodes()
{
	echo 'run_node()'
	##########################################
	# your code here, check destroy_nodes() about how to use loop in the script
	##########################################
	for h in ${nodes[@]}; do
		docker container start $h
	done
}

function create_links()
{
	echo 'create_links()'
	echo "expose each node's namespace"
	mkdir -p /var/run/netns
	
	total=${#nodes[*]}
	echo there are $total nodes
	for ((i=0; i<$total; i=i+1)) do
		echo expose "${nodes[$i]}'s" namespace
		#  Bash 里变量赋值不能有空格。有空格时，shell 会把 pid 当成命令执行
		pid=$(docker inspect -f '{{.State.Pid}}' ${nodes[$i]})
		ln -sf /proc/$pid/ns/net /var/run/netns/$pid

	##########################################
	# your code here
	##########################################
		ip netns exec $pid ip link set lo up
	done
	total=${#links[*]}
	echo there are $total items of \<node1 nic1 ip1 node2 nic2 ip2\>
	for ((i=0; i<$total; i=i+6)) do
	# 节点1/节点1网卡名/节点1IP/节点2/节点2网卡名/节点2IP
		echo create the link for ${links[$i]} ${links[$i+1]} ${links[$i+2]} ${links[$i+3]} ${links[$i+4]} ${links[$i+5]}
	##########################################
	# your code here
	##########################################
		ip link add ${links[$i+1]} type veth peer name ${links[$i+4]} 
		pid1=$(docker inspect -f '{{.State.Pid}}' ${links[$i]})
		pid2=$(docker inspect -f '{{.State.Pid}}' ${links[$i+3]})
		ip link set ${links[$i+1]} netns $pid1
		ip link set ${links[$i+4]} netns $pid2
		ip netns exec $pid1 ip link set ${links[$i+1]} up
		ip netns exec $pid2 ip link set ${links[$i+4]} up
		ip netns exec $pid1 ip addr add ${links[$i+2]} dev ${links[$i+1]}
		ip netns exec $pid2 ip addr add ${links[$i+5]} dev ${links[$i+4]}
	done
}


function stop_nodes()
{
	echo 'stop_nodes()'
	##########################################
	# your code here
	##########################################
	for h in ${nodes[@]}; do
		docker container stop $h
	done
}


function destroy_nodes()
{
	echo 'destroy_nodes()'
	for h in ${nodes[@]}; do
		echo destroy $h
		docker container rm -f $h
	##########################################
	# your code here
	##########################################
	done
}
function destroy_image()
{
	echo 'destroy_image()'
	echo destroy image node
	docker image rm node  
	##########################################
	# your code here
	##########################################
}

function configure_routes()
{
	echo 'configure_route()'
	# 如果“应该出去的网卡”和“这个包实际进来的网卡”对不上，内核就可能把包丢掉。
	
	for h in ${nodes[@]}; do
		echo disable rp_filter on $h
		docker exec $h sysctl -w net.ipv4.conf.all.rp_filter=0
		docker exec $h sysctl -w net.ipv4.conf.default.rp_filter=0
		# Per-interface rp_filter stays at 2 unless we disable it explicitly.
		docker exec $h sh -c 'for f in /proc/sys/net/ipv4/conf/*/rp_filter; do echo 0 > "$f"; done'
	done

	# configure routers with ip_forward 1
	for h in r1 r2 r3 r4 r5; do
		echo configure $h with ip_forward
		# 开启IP转发
		docker exec $h sysctl -w net.ipv4.ip_forward=1
		docker exec $h cat /proc/sys/net/ipv4/ip_forward
	##########################################
	# your code here
	##########################################
	done
	
	# add routing rules
	##########################################
	# your code here
	##########################################
	# h1 -> h2 
	# h2 -> h1
	# 避免重复执行时报 File exists
	docker exec h1 ip route replace default via 111.0.0.2
	docker exec h2 ip route replace default via 111.0.6.1
	# 路由器按网段转发
	docker exec r1 ip route replace 111.0.6.0/24 via 111.0.1.2
	docker exec r2 ip route replace 111.0.6.0/24 via 111.0.2.2
	docker exec r3 ip route replace 111.0.6.0/24 via 111.0.3.2

	docker exec r5 ip route replace 111.0.0.0/24 via 111.0.5.1
	docker exec r4 ip route replace 111.0.0.0/24 via 111.0.4.1
}

# 有参数时，调用函数还是直接写函数名，后面空格跟参数
case $1 in 
	"-ci")
		create_image
		;;
	"-cn")
		create_nodes
		;;
	"-rn")
		run_nodes
		;;
	"-cl")
		create_links
		;;
	"-sn")
		stop_nodes
		;;
	"-dn")
		destroy_nodes
		;;
	"-di")
		destroy_image
		;;
	"-cr")
		configure_routes
		;;
	*)
		echo "input error !"
		;;
esac
