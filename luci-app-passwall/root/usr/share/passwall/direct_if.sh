#!/bin/sh
# PassWall Direct-IF 模块
# 处理Direct-IF节点的策略路由配置

# 确保echolog函数可用（支持分级日志）
if ! command -v echolog >/dev/null 2>&1; then
	echolog() {
		local level="${1:-info}"
		local message="$2"
		
		# 如果只有一个参数，默认为info级别
		if [ $# -eq 1 ]; then
			message="$1"
			level="info"
		fi
		
		# 检查日志级别
		case "${LOG_LEVEL:-info}" in
			"trace") allowed_levels="trace debug info warn error" ;;
			"debug") allowed_levels="debug info warn error" ;;
			"info")  allowed_levels="info warn error" ;;
			"warn")  allowed_levels="warn error" ;;
			"error") allowed_levels="error" ;;
			*) allowed_levels="info warn error" ;;
		esac
		
		# 检查当前级别是否允许输出
		echo "$allowed_levels" | grep -q "\b$level\b" || return 0
		
		local d="$(date "+%Y-%m-%d %H:%M:%S")"
		local prefix="[$level]"
		mkdir -p /tmp/log
		echo -e "$d $prefix: $message" >>${LOG_FILE:-/tmp/log/passwall.log}
	}
fi

# 加载网络辅助函数
[ -f /lib/functions/network.sh ] && . /lib/functions/network.sh

# 提供config_n_get的轻量级实现（用于热插拔等独立场景）
if ! command -v config_n_get >/dev/null 2>&1; then
	config_n_get() {
		# $1=section  $2=option  $3=default
		local _section="$1" _option="$2" _default="$3"
		local _cfg="${CONFIG:-passwall}"
		uci -q get "${_cfg}.${_section}.${_option}" 2>/dev/null || echo "${_default}"
	}
fi

# 轻量级缓存变量函数（减少与app.sh的耦合）
if ! command -v set_cache_var >/dev/null 2>&1; then
	set_cache_var() {
		local var_name="$1"
		local var_value="$2"
		local cache_file="${TMP_PATH:-/tmp/passwall}/var"
		
		(
			flock -x 201
			mkdir -p "$(dirname "$cache_file")"
			# 移除旧值（如果存在）
			sed -i "/^${var_name}=/d" "$cache_file" 2>/dev/null || true
			# 写入新值
			echo "${var_name}=\"${var_value}\"" >> "$cache_file"
		) 201>/var/lock/passwall_cache.lock
	}
fi

if ! command -v get_cache_var >/dev/null 2>&1; then
	get_cache_var() {
		local var_name="$1"
		local cache_file="${TMP_PATH:-/tmp/passwall}/var"
		
		(
			flock -s 201
			[ -f "$cache_file" ] && grep "^${var_name}=" "$cache_file" 2>/dev/null | \
				cut -d'=' -f2- | sed 's/^"//;s/"$//' || true
		) 201>/var/lock/passwall_cache.lock
	}
fi

# Direct-IF全局变量和状态持久化
STATE_FILE="/tmp/.passwall_direct_if_state"

# 默认初始值
_MARK_COUNTER_DEFAULT=256   # 0x100
_TABLE_COUNTER_DEFAULT=500

# 加载持久化计数器（如果存在）
if [ -f "$STATE_FILE" ]; then
	. "$STATE_FILE" 2>/dev/null || true
fi

# 初始化计数器（为空或非数字时回退到默认值）
case "${MARK_COUNTER:-}" in
	''|*[!0-9]*) MARK_COUNTER="$_MARK_COUNTER_DEFAULT";;
esac
case "${TABLE_COUNTER:-}" in
	''|*[!0-9]*) TABLE_COUNTER="$_TABLE_COUNTER_DEFAULT";;
esac

# 脚本作用域的全局计数器
direct_if_mark_base=$MARK_COUNTER
direct_if_table_base=$TABLE_COUNTER

# 持久化更新后的计数器到状态文件
persist_dif_counters() {
	printf '%s\n' "MARK_COUNTER=$direct_if_mark_base" "TABLE_COUNTER=$direct_if_table_base" > "$STATE_FILE" 2>/dev/null || true
}

# 设置Direct-IF节点的策略路由
setup_direct_if() {
	local node="$1"
	local iface=$(config_n_get $node interface_name)  # 专用接口字段（去掉前缀后的名称）
	local mark=$(config_n_get $node routing_mark)     # 专用标记字段（去掉前缀后的名称）
	local table_id=$(config_n_get $node table_id)
	local source=$(config_n_get $node source_address)
	local ipv6_support=$(config_n_get $node ipv6_support 0)
	
	# 自动分配mark和table_id（如果未指定）
	local uci_changed=0
	[ -z "$mark" ] && {
		# 检查mark范围，防止超出0x3FF掩码范围
		if [ "$direct_if_mark_base" -gt 1023 ]; then  # 0x3FF = 1023
			echolog warn "Direct-IF mark范围即将超出0x3FF，从0x300重新开始"
			direct_if_mark_base=768  # 0x300
		fi
		mark="$direct_if_mark_base"
		direct_if_mark_base=$((direct_if_mark_base + 1))

		# 更新持久计数器
		persist_dif_counters
		
		# 标记需要写入UCI（延迟提交）
		uci set "$CONFIG.$node.routing_mark=$mark"
		uci_changed=1
	}
	
	# 验证手动指定的mark是否在合理范围内
	if [ "$mark" -lt 256 ] || [ "$mark" -gt 1023 ]; then  # 0x100-0x3FF
		echolog error "Direct-IF 路由标记$mark超出推荐范围(256-1023)，可能与其他系统冲突"
		return 1
	fi
	
	[ -z "$table_id" ] && {
		table_id="$direct_if_table_base"
		direct_if_table_base=$((direct_if_table_base + 1))

		# 更新持久计数器
		persist_dif_counters
		
		# 标记需要写入UCI（延迟提交）
		uci set "$CONFIG.$node.table_id=$table_id"
		uci_changed=1
	}
	
	# 统一提交UCI更改，减少flash写入
	[ "$uci_changed" = "1" ] && uci commit "$CONFIG"
	
	# 参数检查
	[ -z "$iface" ] && {
		echolog error "Direct-IF 未指定出站接口，无法设置！"
		return 1
	}
	
	# 检查接口是否存在
	local device
	network_get_device device "$iface" || device="$iface"
	ip link show dev "$device" >/dev/null 2>&1
	[ $? -ne 0 ] && {
		echolog error "Direct-IF 接口 '$device' 不存在，无法设置！"
		return 1
	}
	
	# 获取接口IPv4地址（用于设置源地址）
	[ -z "$source" ] && {
		network_get_ipaddr source "$iface"
	}
	
	# 创建或更新路由表名称（防止重复，加锁防止并发竞态）
	local table_name="psw_dif_${table_id}"
	(
		flock -x 200
		sed -i "/^$table_id\s/d" /etc/iproute2/rt_tables 2>/dev/null
		echo "$table_id $table_name" >> /etc/iproute2/rt_tables
	) 200>/var/lock/passwall_rt_tables.lock
	
	# 设置IPv4策略路由规则（使用掩码将整个Direct-IF区间映射）
	ip rule del pref 8600 fwmark "$mark" lookup "$table_id" 2>/dev/null || true
	ip rule add pref 8600 fwmark "$mark" lookup "$table_id"
	
	# 清理旧路由表
	ip route flush table "$table_id" 2>/dev/null || true
	
	# 设置IPv4默认路由
	local gateway
	network_get_gateway gateway "$iface"
	
	if [ -n "$gateway" ] && [ -n "$source" ]; then
		# 使用网关和源地址
		ip route add default via "$gateway" dev "$device" src "$source" table "$table_id" || true
	elif [ -n "$gateway" ]; then
		# 只使用网关
		ip route add default via "$gateway" dev "$device" table "$table_id" || true
	elif [ -n "$source" ]; then
		# 只使用源地址
		ip route add default dev "$device" src "$source" table "$table_id" || true
	else
		# 只使用设备
		ip route add default dev "$device" table "$table_id" || true
	fi
	
	echolog info "Direct-IF 成功设置IPv4策略路由，接口: '$iface($device)', 标记: $mark, 表: $table_id"
		
	# 存储基本配置供iptables/nftables使用
	set_cache_var "direct_if_${node}_iface" "$iface"
	set_cache_var "direct_if_${node}_device" "$device"
	set_cache_var "direct_if_${node}_mark" "$mark"
	set_cache_var "direct_if_${node}_table" "$table_id"
	
	# 设置IPv6策略路由（仅当用户明确开启IPv6支持时）
	if [ "$ipv6_support" = "1" ]; then
		# 检查接口是否有IPv6地址
		local ipv6_addr
		network_get_ipaddr6 ipv6_addr "$iface"
		
		if [ -n "$ipv6_addr" ]; then
			# IPv6表ID计算：<1000时+1000，>=1000时+100
			local ipv6_table_id
			if [ "$table_id" -lt 1000 ]; then
				ipv6_table_id=$((table_id + 1000))
			else
				ipv6_table_id=$((table_id + 100))
			fi
			local ipv6_table_name="psw_dif6_${ipv6_table_id}"
			
			# 检查IPv6 table ID是否会冲突
			if [ $ipv6_table_id -gt 65535 ]; then
				echolog warn "Direct-IF IPv6表ID $ipv6_table_id 超出系统上限(65535)，建议使用更小的基础table_id(当前:$table_id)，跳过IPv6配置"
			else
				# 更新路由表名称
				(
					flock -x 200
					sed -i "/^$ipv6_table_id\s/d" /etc/iproute2/rt_tables 2>/dev/null
					echo "$ipv6_table_id $ipv6_table_name" >> /etc/iproute2/rt_tables
				) 200>/var/lock/passwall_rt_tables.lock
				
				# 设置IPv6策略路由规则
				ip -6 rule del pref 8600 fwmark "$mark" lookup "$ipv6_table_id" 2>/dev/null || true
				ip -6 rule add pref 8600 fwmark "$mark" lookup "$ipv6_table_id"
				
				# 清理旧IPv6路由表
				ip -6 route flush table "$ipv6_table_id" 2>/dev/null || true
				
				# 设置IPv6默认路由
				local ipv6_gateway source6
				network_get_gateway6 ipv6_gateway "$iface"
				[ -z "$source6" ] && source6="$ipv6_addr"
				
				if [ -n "$ipv6_gateway" ] && [ -n "$source6" ]; then
					ip -6 route add default via "$ipv6_gateway" dev "$device" src "$source6" table "$ipv6_table_id" || true
				elif [ -n "$ipv6_gateway" ]; then
					ip -6 route add default via "$ipv6_gateway" dev "$device" table "$ipv6_table_id" || true
				elif [ -n "$source6" ]; then
					ip -6 route add default dev "$device" src "$source6" table "$ipv6_table_id" || true
				else
					ip -6 route add default dev "$device" table "$ipv6_table_id" || true
				fi
				
				
				# 存储IPv6配置
				set_cache_var "direct_if_${node}_ipv6_table" "$ipv6_table_id"
				set_cache_var "direct_if_${node}_ipv6_enabled" "1"
				
				echolog info "Direct-IF 成功设置IPv6策略路由，表: $ipv6_table_id"
			fi
		else
			echolog debug "Direct-IF 接口 '$iface' 无IPv6地址，跳过IPv6配置"
		fi
	fi
	
	return 0
}

# 清理Direct-IF节点的路由设置
cleanup_direct_if() {
	local node="$1"
	local mark=$(get_cache_var "direct_if_${node}_mark")
	local table_id=$(get_cache_var "direct_if_${node}_table")
	local ipv6_table_id=$(get_cache_var "direct_if_${node}_ipv6_table")
	
	# 清理IPv4规则和路由
	[ -n "$mark" ] && [ -n "$table_id" ] && {
		ip rule del pref 8600 fwmark "$mark" lookup "$table_id" 2>/dev/null || true
	}
	[ -n "$table_id" ] && {
		ip route flush table "$table_id" 2>/dev/null || true
	}
	
	# 清理IPv6规则和路由  
	[ -n "$mark" ] && [ -n "$ipv6_table_id" ] && {
		ip -6 rule del pref 8600 fwmark "$mark" lookup "$ipv6_table_id" 2>/dev/null || true
	}
	[ -n "$ipv6_table_id" ] && {
		ip -6 route flush table "$ipv6_table_id" 2>/dev/null || true
	}
}

# 刷新Direct-IF节点路由（用于hotplug）
refresh_direct_if_routes() {
	local node="$1"
	local table_id=$(get_cache_var "direct_if_${node}_table")
	local ipv6_table_id=$(get_cache_var "direct_if_${node}_ipv6_table")
	local mark=$(get_cache_var "direct_if_${node}_mark")
	local iface=$(config_n_get "$node" "interface_name")
	local source=$(config_n_get "$node" "source_address")
	
	[ -z "$table_id" ] || [ -z "$mark" ] || [ -z "$iface" ] && return 1
	
	# 获取设备名和网关
	local device gateway
	network_get_device device "$iface" || device="$iface"
	network_get_gateway gateway "$iface"
	[ -z "$source" ] && network_get_ipaddr source "$iface"
	
	# 检查设备是否存在
	ip link show dev "$device" >/dev/null 2>&1 || return 1
	
	# 清理并重新设置IPv4路由
	ip route flush table "$table_id" 2>/dev/null || true
	
	if [ -n "$gateway" ] && [ -n "$source" ]; then
		ip route add default via "$gateway" dev "$device" src "$source" table "$table_id" || true
	elif [ -n "$gateway" ]; then
		ip route add default via "$gateway" dev "$device" table "$table_id" || true
	elif [ -n "$source" ]; then
		ip route add default dev "$device" src "$source" table "$table_id" || true
	else
		ip route add default dev "$device" table "$table_id" || true
	fi
	
	# IPv6处理（如果需要）
	if [ -n "$ipv6_table_id" ]; then
		local ipv6_gateway source6
		network_get_gateway6 ipv6_gateway "$iface"
		network_get_ipaddr6 source6 "$iface"
		
		ip -6 route flush table "$ipv6_table_id" 2>/dev/null || true
		
		if [ -n "$ipv6_gateway" ] && [ -n "$source6" ]; then
			ip -6 route add default via "$ipv6_gateway" dev "$device" src "$source6" table "$ipv6_table_id" || true
		elif [ -n "$ipv6_gateway" ]; then
			ip -6 route add default via "$ipv6_gateway" dev "$device" table "$ipv6_table_id" || true
		elif [ -n "$source6" ]; then
			ip -6 route add default dev "$device" src "$source6" table "$ipv6_table_id" || true
		else
			ip -6 route add default dev "$device" table "$ipv6_table_id" || true
		fi
	fi
	
	# 确保策略规则存在（若被清理则重建）
	ip rule show pref 8600 2>/dev/null | grep -q "fwmark $mark.*lookup $table_id" || {
		ip rule add pref 8600 fwmark "$mark" lookup "$table_id"
		echolog info "Direct-IF 重建IPv4策略路由规则，标记: $mark, 表: $table_id"
	}
	
	if [ -n "$ipv6_table_id" ]; then
		ip -6 rule show pref 8600 2>/dev/null | grep -q "fwmark $mark.*lookup $ipv6_table_id" || {
			ip -6 rule add pref 8600 fwmark "$mark" lookup "$ipv6_table_id"
			echolog info "Direct-IF 重建IPv6策略路由规则，标记: $mark, 表: $ipv6_table_id"
		}
	fi
}

# 批量清理所有Direct-IF节点（用于stop函数）
cleanup_all_direct_if() {
	local direct_if_marks=""
	local direct_if_tables=""
	local direct_if_ipv6_tables=""
	
	[ -s "$TMP_PATH/var" ] && {
		direct_if_marks=$(grep -E 'direct_if_.*_mark=' "$TMP_PATH/var" 2>/dev/null | awk -F '=' '{print $2}' | tr -d '"' || true)
		direct_if_tables=$(grep -E 'direct_if_.*_table=' "$TMP_PATH/var" 2>/dev/null | awk -F '=' '{print $2}' | tr -d '"' || true)
		direct_if_ipv6_tables=$(grep -E 'direct_if_.*_ipv6_table=' "$TMP_PATH/var" 2>/dev/null | awk -F '=' '{print $2}' | tr -d '"' || true)
	}
	
	# 清理IPv4规则（带掩码并检查存在性）
	for mark in $direct_if_marks; do
		[ -n "$mark" ] || continue
		# 动态解析table_id，使用更新的掩码
		local mark_hex=$(printf '0x%x' "$mark")
		local table_id=$(ip rule list 2>/dev/null | awk -v md="$mark" -v mh="$mark_hex" 'index($0,"fwmark") && ($0 ~ md || $0 ~ mh) {for(i=1;i<=NF;i++){if($i=="lookup"){print $(i+1);break}}}')
		if [ -n "$table_id" ]; then
			ip rule del pref 8600 fwmark "$mark" lookup "$table_id" 2>/dev/null || true
		fi
	done
	
	for table in $direct_if_tables; do
		[ -n "$table" ] && ip route flush table "$table" 2>/dev/null || true
	done
	
	# 清理IPv6规则（如果有，带掩码并检查存在性）
	for mark in $direct_if_marks; do
		[ -n "$mark" ] || continue
		# 动态解析IPv6 table_id，使用更新的掩码
		local mark_hex=$(printf '0x%x' "$mark")
		local ipv6_table_id=$(ip -6 rule list 2>/dev/null | awk -v md="$mark" -v mh="$mark_hex" 'index($0,"fwmark") && ($0 ~ md || $0 ~ mh) {for(i=1;i<=NF;i++){if($i=="lookup"){print $(i+1);break}}}')
		if [ -n "$ipv6_table_id" ]; then
			ip -6 rule del pref 8600 fwmark "$mark" lookup "$ipv6_table_id" 2>/dev/null || true
		fi
	done
	
	for table in $direct_if_ipv6_tables; do
		[ -n "$table" ] && ip -6 route flush table "$table" 2>/dev/null || true
	done
	
	# 清理rt_tables中的临时表名
	if [ -f "/etc/iproute2/rt_tables" ]; then
		(
			flock -x 200
			# 删除IPv4表条目（精确匹配table_id）
			for table in $direct_if_tables; do
				[ -n "$table" ] && sed -i "/^$table\\s/d" /etc/iproute2/rt_tables 2>/dev/null || true
			done
			# 删除IPv6表条目（精确匹配table_id）  
			for table in $direct_if_ipv6_tables; do
				[ -n "$table" ] && sed -i "/^$table\\s/d" /etc/iproute2/rt_tables 2>/dev/null || true
			done
			# 兜底：删除所有psw_dif开头的表条目
			sed -i '/\spsw_dif/d' /etc/iproute2/rt_tables 2>/dev/null || true
		) 200>/var/lock/passwall_rt_tables.lock
	fi
	
	# 重置mark和table基数
	direct_if_mark_base=$_MARK_COUNTER_DEFAULT  # reset
	direct_if_table_base=$_TABLE_COUNTER_DEFAULT
	persist_dif_counters
}

# Direct-IF专用的TCP流量标记函数
direct_if_tcp_mark() {
	local node="$1"
	local target="$2"
	local port="$3"  # 保留此参数以维持接口一致性，Direct-IF不使用端口
	local mark=$(get_cache_var "direct_if_${node}_mark")
	local remarks=$(config_n_get "$node" remarks)
	
	# 设置缓存变量，标识这是Direct-IF节点
	set_cache_var "node_${node}_tcp_direct_if" "1"
	
	[ -z "$mark" ] && return 1
	
	# 使用add_port_rules_before函数插入规则
	if [ -n "$target" ]; then
		add_port_rules_before "$ipt_m" "PSW_RULE" "CONNMARK --save-mark" \
			"$(comment "Direct-IF:$remarks") -p tcp -m set --match-set $target dst" \
			"$TCP_REDIR_PORTS" "MARK --set-mark $mark"
	else
		add_port_rules_before "$ipt_m" "PSW_RULE" "CONNMARK --save-mark" \
			"$(comment "Direct-IF:$remarks") -p tcp" \
			"$TCP_REDIR_PORTS" "MARK --set-mark $mark"
	fi
}

# Direct-IF专用的UDP流量标记函数
direct_if_udp_mark() {
	local node="$1"
	local target="$2"
	local port="$3"  # 保留此参数以维持接口一致性，Direct-IF不使用端口
	local mark=$(get_cache_var "direct_if_${node}_mark")
	local remarks=$(config_n_get "$node" remarks)
	
	# 设置缓存变量，标识这是Direct-IF节点
	set_cache_var "node_${node}_udp_direct_if" "1"
	
	[ -z "$mark" ] && return 1
	
	# 使用add_port_rules_before函数插入规则
	if [ -n "$target" ]; then
		add_port_rules_before "$ipt_m" "PSW_RULE" "CONNMARK --save-mark" \
			"$(comment "Direct-IF:$remarks") -p udp -m set --match-set $target dst" \
			"$UDP_REDIR_PORTS" "MARK --set-mark $mark"
	else
		add_port_rules_before "$ipt_m" "PSW_RULE" "CONNMARK --save-mark" \
			"$(comment "Direct-IF:$remarks") -p udp" \
			"$UDP_REDIR_PORTS" "MARK --set-mark $mark"
	fi
}

# Direct-IF专用的nftables TCP流量标记函数
direct_if_nft_tcp_mark() {
	local node="$1"
	local target="$2"
	local port="$3"  # 保留此参数以维持接口一致性，Direct-IF不使用端口
	local mark=$(get_cache_var "direct_if_${node}_mark")
	local remarks=$(config_n_get "$node" remarks)
	local ipv6_enabled=$(get_cache_var "direct_if_${node}_ipv6_enabled")
	
	# 设置缓存变量，标识这是Direct-IF节点
	set_cache_var "node_${node}_tcp_direct_if" "1"
	
	[ -z "$mark" ] && return 1
	
	# 添加IPv4标记规则（在ct mark set mark规则之前插入）
	local handle=$(get_connmark_save_handle)
	if [ -n "$target" ] && [ -n "$handle" ]; then
		nft insert rule $NFTABLE_NAME PSW_RULE position $handle \
			ip daddr @$target tcp dport \{ $TCP_REDIR_PORTS \} \
			counter mark set $mark comment \"Direct-IF:$remarks\" || true
	elif [ -n "$handle" ]; then
		nft insert rule $NFTABLE_NAME PSW_RULE position $handle \
			tcp dport \{ $TCP_REDIR_PORTS \} \
			counter mark set $mark comment \"Direct-IF:$remarks\" || true
	elif [ -n "$target" ]; then
		# fallback: 添加到链首位置
		nft insert rule $NFTABLE_NAME PSW_RULE position 0 \
			ip daddr @$target tcp dport \{ $TCP_REDIR_PORTS \} \
			counter mark set $mark comment \"Direct-IF:$remarks\" || true
	else
		# fallback: 添加到链首位置 
		nft insert rule $NFTABLE_NAME PSW_RULE position 0 \
			tcp dport \{ $TCP_REDIR_PORTS \} \
			counter mark set $mark comment \"Direct-IF:$remarks\" || true
	fi
	
	# IPv6规则（仅在明确启用时）
	if [ "$ipv6_enabled" = "1" ] && [ "$PROXY_IPV6" = "1" ]; then
		if [ -n "$target" ] && [ -n "$handle" ]; then
			nft insert rule $NFTABLE_NAME PSW_RULE position $handle \
				ip6 daddr @${target}6 tcp dport \{ $TCP_REDIR_PORTS \} \
				counter mark set $mark comment \"Direct-IF-IPv6:$remarks\" || true
		elif [ -n "$handle" ]; then
			nft insert rule $NFTABLE_NAME PSW_RULE position $handle \
				meta l3proto ip6 tcp dport \{ $TCP_REDIR_PORTS \} \
				counter mark set $mark comment \"Direct-IF-IPv6:$remarks\" || true
		fi
	fi
}

# Direct-IF专用的nftables UDP流量标记函数
direct_if_nft_udp_mark() {
	local node="$1"
	local target="$2"
	local port="$3"  # 保留此参数以维持接口一致性，Direct-IF不使用端口
	local mark=$(get_cache_var "direct_if_${node}_mark")
	local remarks=$(config_n_get "$node" remarks)
	local ipv6_enabled=$(get_cache_var "direct_if_${node}_ipv6_enabled")
	
	# 设置缓存变量，标识这是Direct-IF节点
	set_cache_var "node_${node}_udp_direct_if" "1"
	
	[ -z "$mark" ] && return 1
	
	# 添加IPv4标记规则
	local handle=$(get_connmark_save_handle)
	if [ -n "$target" ] && [ -n "$handle" ]; then
		nft insert rule $NFTABLE_NAME PSW_RULE position $handle \
			ip daddr @$target udp dport \{ $UDP_REDIR_PORTS \} \
			counter mark set $mark comment \"Direct-IF:$remarks\" || true
	elif [ -n "$handle" ]; then
		nft insert rule $NFTABLE_NAME PSW_RULE position $handle \
			udp dport \{ $UDP_REDIR_PORTS \} \
			counter mark set $mark comment \"Direct-IF:$remarks\" || true
	elif [ -n "$target" ]; then
		nft insert rule $NFTABLE_NAME PSW_RULE position 0 \
			ip daddr @$target udp dport \{ $UDP_REDIR_PORTS \} \
			counter mark set $mark comment \"Direct-IF:$remarks\" || true
	else
		nft insert rule $NFTABLE_NAME PSW_RULE position 0 \
			udp dport \{ $UDP_REDIR_PORTS \} \
			counter mark set $mark comment \"Direct-IF:$remarks\" || true
	fi
	
	# IPv6规则（仅在明确启用时）
	if [ "$ipv6_enabled" = "1" ] && [ "$PROXY_IPV6" = "1" ]; then
		if [ -n "$target" ] && [ -n "$handle" ]; then
			nft insert rule $NFTABLE_NAME PSW_RULE position $handle \
				ip6 daddr @${target}6 udp dport \{ $UDP_REDIR_PORTS \} \
				counter mark set $mark comment \"Direct-IF-IPv6:$remarks\" || true
		elif [ -n "$handle" ]; then
			nft insert rule $NFTABLE_NAME PSW_RULE position $handle \
				meta l3proto ip6 udp dport \{ $UDP_REDIR_PORTS \} \
				counter mark set $mark comment \"Direct-IF-IPv6:$remarks\" || true
		fi
	fi
}

# 处理ACL规则中的Direct-IF节点（由app.sh调用）
setup_acl_direct_if_nodes() {
	local section="$1"
	local enabled tcp_node udp_node
	
	config_get enabled "$section" "enabled" "0"
	[ "$enabled" = "0" ] && return 0
	
	config_get tcp_node "$section" "tcp_node"
	config_get udp_node "$section" "udp_node"
	
	for node in $tcp_node $udp_node; do
		[ -z "$node" ] || [ "$node" = "nil" ] || [ "$node" = "default" ] || [ "$node" = "tcp" ] && continue
		if [ "$(config_n_get $node type)" = "Direct-IF" ]; then
			if ! setup_direct_if $node; then
				echolog error "ACL规则中的Direct-IF节点 [$(config_n_get $node remarks)] 设置失败"
				set_cache_var "direct_if_${node}_error" "1"
			fi
		fi
	done
}

# Direct-IF状态查询函数（用于调试和监控）
direct_if_status() {
	echo "=== Direct-IF 节点状态 ==="
	echo
	
	# 显示策略路由规则
	echo "IPv4 策略路由规则:"
	ip rule list | grep -E "fwmark|lookup psw_dif" | grep -v "from all lookup" || echo "  无"
	echo
	
	echo "IPv6 策略路由规则:"
	ip -6 rule list | grep -E "fwmark|lookup psw_dif" | grep -v "from all lookup" || echo "  无"
	echo
	
	# 显示路由表内容
	echo "Direct-IF 路由表:"
	for table in $(ip route list table all | grep -o "table psw_dif[0-9]*" | awk '{print $2}' | sort -u); do
		echo "  表 $table:"
		ip route list table "$table" | sed 's/^/    /'
	done
	
	# 显示缓存的节点信息
	if [ -f "${TMP_PATH:-/tmp/passwall}/var" ]; then
		echo
		echo "已配置的Direct-IF节点:"
		grep -E "direct_if_.*_mark=" "${TMP_PATH:-/tmp/passwall}/var" 2>/dev/null | while read line; do
			local var_name=$(echo "$line" | cut -d'=' -f1)
			local node=$(echo "$var_name" | sed 's/direct_if_//;s/_mark//')
			local mark=$(get_cache_var "direct_if_${node}_mark")
			local table=$(get_cache_var "direct_if_${node}_table")
			local iface=$(get_cache_var "direct_if_${node}_iface")
			local error=$(get_cache_var "direct_if_${node}_error")
			
			echo "  节点: $node"
			echo "    接口: $iface"
			echo "    标记: $mark (0x$(printf '%x' $mark))"
			echo "    路由表: $table"
			[ -n "$error" ] && echo "    状态: 错误" || echo "    状态: 正常"
		done
	fi
}