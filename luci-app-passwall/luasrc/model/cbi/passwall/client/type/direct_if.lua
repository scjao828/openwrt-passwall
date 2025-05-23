local m, s = ...

local api = require "luci.passwall.api"

-- 定义新节点类型
local type_name = "Direct-IF"
local option_prefix = "direct_if_"

local function _n(name)
	return option_prefix .. name
end

-- 添加到节点类型列表
s.fields["type"]:value(type_name, translate("Direct Interface"))

-- 隐藏protocol字段，但提供兼容性
o = s:option(ListValue, _n("protocol"))
o:depends({ [_n("__hide")] = "1" })
o:value("_direct", translate("Direct"))
o.default = "_direct"
o.rewrite_option = "protocol"

-- 接口配置（使用专用字段）
o = s:option(Value, _n("interface_name"), translate("Outbound Interface"))
o:depends({ type = type_name })
o.placeholder = "eth1, pppoe-wan..."
o.rmempty = false

-- 选择网络接口的下拉列表
local interfaces = {}
local net = require "luci.model.network".init()
for _, iface in ipairs(net:get_networks()) do
	local device = iface:get_interface()
	if device then
		interfaces[#interfaces+1] = {
			name = iface:name(),
			device = device:name(),
			description = iface:get_i18n()
		}
	end
end

for _, iface in ipairs(interfaces) do
	o:value(iface.name, iface.description .. " (" .. iface.name .. ")")
end

-- 路由标记（使用专用字段，起始值0x100）
o = s:option(Value, _n("routing_mark"), translate("Routing Mark"))
o:depends({ type = type_name })
o.datatype = "uinteger"
o.default = "256"  -- 0x100
o.rmempty = true  -- 留空时自动分配
o.description = translate("fwmark for policy routing (0x100-0x3FF recommended)")
-- 区间校验和冲突检查
o.validate = function(self, value, section)
	if value and value ~= "" then
		local mark = tonumber(value)
		if not mark or mark < 256 or mark > 1023 then  -- 0x100-0x3FF
			return nil, translate("Routing mark must be between 256 (0x100) and 1023 (0x3FF)")
		end
		
		-- 检查是否与其他Direct-IF节点冲突
		local uci = require "luci.model.uci".cursor()
		uci:foreach("passwall", "nodes", function(s)
			if s[".name"] ~= section and s.type == "Direct-IF" and s.routing_mark == value then
				return nil, translate("Routing mark conflicts with another Direct-IF node")
			end
		end)
	end
	return value
end

-- 路由表ID
o = s:option(Value, _n("table_id"), translate("Routing Table ID"))
o:depends({ type = type_name })
o.datatype = "uinteger"
o.default = "500"
o.rmempty = true  -- 留空时自动分配
o.description = translate("Routing table ID (500-999 recommended). IPv6 table will be +1000 if <1000, otherwise +100")
-- 区间校验和冲突检查
o.validate = function(self, value, section)
	if value and value ~= "" then
		local table_id = tonumber(value)
		if not table_id or table_id < 1 or table_id > 65535 then
			return nil, translate("Table ID must be between 1 and 65535")
		end
		
		-- 检查IPv6表号是否会超限
		local ipv6_table_id
		if table_id < 1000 then
			ipv6_table_id = table_id + 1000
		else
			ipv6_table_id = table_id + 100
		end
		
		if ipv6_table_id > 65535 then
			return nil, translate("IPv6 table ID would exceed 65535, please use smaller table ID")
		end
		
		-- 检查是否与其他Direct-IF节点冲突
		local uci = require "luci.model.uci".cursor()
		local has_conflict = false
		local conflict_msg = nil
		
		uci:foreach("passwall", "nodes", function(s)
			if s[".name"] ~= section and s.type == "Direct-IF" then
				-- 检查主表ID冲突
				if s.table_id == value then
					has_conflict = true
					conflict_msg = translate("Table ID conflicts with another Direct-IF node")
					return false
				end
				
				-- 检查IPv6表ID冲突
				local other_table = tonumber(s.table_id)
				if other_table then
					local other_ipv6
					if other_table < 1000 then
						other_ipv6 = other_table + 1000
					else
						other_ipv6 = other_table + 100
					end
					
					-- 检查当前节点的IPv6表是否与其他节点的IPv4/IPv6表冲突
					if ipv6_table_id == other_table or ipv6_table_id == other_ipv6 then
						has_conflict = true
						conflict_msg = translate("IPv6 table ID conflicts with another Direct-IF node")
						return false
					end
					
					-- 检查当前节点的IPv4表是否与其他节点的IPv6表冲突
					if table_id == other_ipv6 then
						has_conflict = true
						conflict_msg = translate("Table ID conflicts with another node's IPv6 table")
						return false
					end
				end
			end
		end)
		
		if has_conflict then
			return nil, conflict_msg
		end
	end
	return value
end

-- 源地址（可选）
o = s:option(Value, _n("source_address"), translate("Source Address"))
o:depends({ type = type_name })
o.datatype = "ipaddr"
o.placeholder = translate("Optional")
o.rmempty = true

-- IPv6支持选项（简单开关）
o = s:option(Flag, _n("ipv6_support"), translate("IPv6 Support"))
o:depends({ type = type_name })
o.default = "0"  -- 默认关闭
o.rmempty = false
o.description = translate("Enable IPv6 support for this interface")

-- SOCKS代理选项（使用microsocks提供）
o = s:option(Flag, _n("socks_enabled"), translate("Provide SOCKS Proxy"))
o:depends({ type = type_name })
o.default = "0"  -- 默认关闭
o.rmempty = false
o.description = translate("Use microsocks to provide SOCKS5 proxy for this Direct-IF node")

-- 注册类型
api.luci_types(arg[1], m, s, type_name, option_prefix)