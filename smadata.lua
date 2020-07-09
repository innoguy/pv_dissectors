--[[

    Name         :  smadata.lua
    Author       :  Guy Coen
    Company      :  Mind4Energy NV

    Description  
        This Lua dissector for Wireshark dissects the SMA Data protocol for 
        the following SMA inverters:
            
		- To be completed

    Current limitations
        - Only tested with Wireshark 3.2.5
       
--]]

local debug_level = {
    DISABLED = 0,
    LEVEL_1  = 1,
    LEVEL_2  = 2
}

local DEBUG = debug_level.LEVEL_1

local default_settings =
{
    debug_level  = DEBUG,
    port         = 24272,
    heur_enabled = false,
}

local args={...} -- get passed-in args
if args and #args > 0 then
    for _, arg in ipairs(args) do
        local name, value = arg:match("(.+)=(.+)")
        if name and value then
            if tonumber(value) then
                value = tonumber(value)
            elseif value == "true" or value == "TRUE" then
                value = true
            elseif value == "false" or value == "FALSE" then
                value = false
            elseif value == "DISABLED" then
                value = debug_level.DISABLED
            elseif value == "LEVEL_1" then
                value = debug_level.LEVEL_1
            elseif value == "LEVEL_2" then
                value = debug_level.LEVEL_2
            else
                error("invalid commandline argument value")
            end
        else
            error("invalid commandline argument syntax")
        end

        default_settings[name] = value
    end
end

local dprint = function() end
local dprint2 = function() end
local function reset_debug_level()
    if default_settings.debug_level > debug_level.DISABLED then
        dprint = function(...)
            print(table.concat({"Lua:", ...}," "))
        end

        if default_settings.debug_level > debug_level.LEVEL_1 then
            dprint2 = dprint
        end
    end
end
-- call it now
reset_debug_level()

dprint2("Wireshark version = ", get_version())
dprint2("Lua version = ", _VERSION)

----------------------------------------------
-- Assert Wireshark version

local major, minor, micro = get_version():match("(%d+)%.(%d+)%.(%d+)")
if major and tonumber(major) <= 1 and ((tonumber(minor) <= 10) or (tonumber(minor) == 11 and tonumber(micro) < 3)) then
        error(  "Sorry, but your Wireshark/Tshark version ("..get_version()..") is too old for this script!\n"..
                "This script needs Wireshark/Tshark version 1.11.3 or higher.\n" )
end
assert(ProtoExpert.new, "Wireshark does not have the ProtoExpert class, so it's too old - get the latest 1.11.3 or higher")

local smd = Proto("sma-data","SMA Data Protocol")

local cmd_table = {
		[01] = "CMD_GET_NET",				
		[02] = "CMD_SEARCH_DEVICE",			
		[03] = "CMD_CFG_NETADR",			
		[04] = "CMD_SET_GRPADR",
		[05] = "CMD_DEL_GRPADR",
		[06] = "CMD_GET_NET_START",
		[09] = "CMD_GET_CINFO",
		[10] = "CMD_SYN_ONLINE",
		[11] = "CMD_GET_DATA",
		[12] = "CMD_SET_DATA",
		[13] = "CMD_GET_SINFO",
		[15] = "CMD_SET_MPARA",
		[20] = "CMD_GET_MTIME",
		[21] = "CMD_SET_MTIME",
		[30] = "CMD_GET_BINFO",
		[31] = "CMD_GET_BIN",
		[32] = "CMD_SET_BIN",
		[40] = "CMD_PDELIMIT",			
		[50] = "CMD_TNR_VERIFY",
		[51] = "CMD_VAR_VALUE",
		[52] = "CMD_VAR_FIND",
		[53] = "CMD_VAR_STATUS_OUT",
		[54] = "CMD_VAR_DEFINE_OUT",
		[55] = "CMD_VAR_STATUS_IN",
		[56] = "CMD_VAR_DEFINE_IN",
		[60] = "CMD_TEAM_FUNCTION"
}


local start   = ProtoField.new("smd.start",   "smd.start" ,  ftypes.UINT8, nil, base.HEX) -- 7E
local address = ProtoField.new("smd.address", "smd.magic1",  ftypes.UINT8, nil, base.HEX) -- FF
local control = ProtoField.new("smd.control", "smd.control", ftypes.UINT8, nil, base.HEX) -- 03

header_table = {
    [0x4041] = "SMA Data Telegram",
    [0x4051] = "TCP/IP Supplementary Module",
    [0x4043] = "Software Update System"
}

local header  = ProtoField.new("smd.header" , "smd.header",  ftypes.UINT16, header_table, base.HEX, 0xffff)
local data    = ProtoField.new("smd.data",    "smd.data",    ftypes.BYTES)
local fcs     = ProtoField.new("smd.fcs" ,    "smd.fcs",     ftypes.UINT16, nil, base.HEX)
local stop    = ProtoField.new("smd.stop" ,   "smd.stop",    ftypes.UINT8, nil, base.HEX) -- 7E

local src = ProtoField.new("smd.data.src", "smd.data.src", 
		ftypes.UINT16, nil, base.HEX)
local dst = ProtoField.new("smd.data.dst",   "smd.data.dst",    
		ftypes.UINT16, nil, base.HEX)

local ctl1 = {
    [0x0] = "Network address mode",
    [0x1] = "Group address mode"
}

local ctl2 = {
    [0x0] = "Inquiry",
    [0x1] = "Response"
}

local ctl3 = {
    [0x0] = "Non blockng",
    [0x1] = "Blocking"
}

local ctl = ProtoField.new("smd.data.ctl", "smd.data.ctl",       
	ftypes.UINT8, ctl, base.HEX,  0xD0)
local ctl1 = ProtoField.new("smd.data.ctl1", "smd.data.ctl1",    
	ftypes.UINT8, ctl1, base.HEX, 0x80)
local ctl2 = ProtoField.new("smd.data.ctl2", "smd.data.ctl2",    
	ftypes.UINT8, ctl2, base.HEX, 0x40)
local ctl3 = ProtoField.new("smd.data.ctl3", "smd.data.ctl3",    
	ftypes.UINT8, ctl3, base.HEX, 0x10)


local cnt = ProtoField.new("smd.data.cnt",   "smd.data.cnt",    ftypes.UINT8)
local cmd = ProtoField.new("smd.data.cmd",   "smd.data.cmd",    ftypes.UINT8, cmd_table, base.HEX, 0xff)



--------------------------------------------------------------------------------
-- preferences handling stuff
--------------------------------------------------------------------------------

-- a "enum" table for our enum pref, as required by Pref.enum()
-- having the "index" number makes ZERO sense, and is completely illogical
-- but it's what the code has expected it to be for a long time. Ugh.
local debug_pref_enum = {
    { 1,  "Disabled", debug_level.DISABLED },
    { 2,  "Level 1",  debug_level.LEVEL_1  },
    { 3,  "Level 2",  debug_level.LEVEL_2  },
}

smd.prefs.debug = Pref.enum("Debug", default_settings.debug_level,
                            "The debug printing level", debug_pref_enum)

smd.prefs.port  = Pref.uint("Port number", default_settings.port,
                            "The UDP port number for Speedwire")

smd.prefs.heur  = Pref.bool("Heuristic enabled", default_settings.heur_enabled,
                            "Whether heuristic dissection is enabled or not")

----------------------------------------
-- a function for handling prefs being changed
function smd.prefs_changed()
    dprint2("prefs_changed called")

    default_settings.debug_level  = smd.prefs.debug
    reset_debug_level()

    default_settings.heur_enabled = smd.prefs.heur

    if default_settings.port ~= smd.prefs.port then
        -- remove old one, if not 0
        if default_settings.port ~= 0 then
            dprint2("removing Speedwire from port",default_settings.port)
            DissectorTable.get("udp.port"):remove(default_settings.port, smd)
        end
        -- set our new default
        default_settings.port = smd.prefs.port
        -- add new one, if not 0
        if default_settings.port ~= 0 then
            dprint2("adding Speedwire to port",default_settings.port)
            DissectorTable.get("udp.port"):add(default_settings.port, smd)
        end
    end

end

dprint2("Speedwire Prefs registered")

smd.fields = {start, address, control, header, data, fcs, stop,
		src, dst, cnt, cmd, ctl, ctl1, ctl2, ctl3}

----------------------------------------
-- create some expert info fields (this is new functionality in 1.11.3)
-- Expert info fields are very similar to proto fields: they're tied to our protocol,
-- they're created in a similar way, and registered by setting a 'experts' field to
-- a table of them just as proto fields were put into the 'dns.fields' above
-- The old way of creating expert info was to just add it to the tree, but that
-- didn't let the expert info be filterable in wireshark, whereas this way does
local ef_query     = ProtoExpert.new("smd.query.expert", "Speedwire query message",
                                     expert.group.REQUEST_CODE, expert.severity.CHAT)
local ef_response  = ProtoExpert.new("smd.response.expert", "Speedwire response message",
                                     expert.group.RESPONSE_CODE, expert.severity.CHAT)
local ef_ultimate  = ProtoExpert.new("smd.response.ultimate.expert", "Speedwire answer to life, the universe, and everything",
                                     expert.group.COMMENTS_GROUP, expert.severity.NOTE)
-- some error expert info's
local ef_too_short = ProtoExpert.new("smd.too_short.expert", "Speedwire message too short",
                                     expert.group.MALFORMED, expert.severity.ERROR)
local ef_bad_query = ProtoExpert.new("smd.query.missing.expert", "Speedwire query missing or malformed",
                                     expert.group.MALFORMED, expert.severity.WARN)

-- register them
smd.experts = { ef_query, ef_too_short, ef_bad_query, ef_response, ef_ultimate }

function smd.dissector(tvbuf, pktinfo, root)


    length = tvbuf:len()
	if length == 0 then 
	    return 
	end
		
    pktinfo.cols.protocol:set("sma-data")

    local pktlen = tvbuf:reported_length_remaining()
    local tree    = root:add(smd, tvbuf:range(0, pktlen), "SMA Data")
    local subtree = tree:add(smd, tvbuf:range(0, pktlen), "Command")

    tree:add(start ,   tvbuf(0,1))
    tree:add(address , tvbuf(1,1))
    tree:add(control , tvbuf(2,1))
    tree:add(header  , tvbuf(3,2))
    tree:add(data    , tvbuf(5,length-8))
    subtree:add(src, tvbuf(5,2))
    subtree:add(dst, tvbuf(7,2))
    subtree:add(ctl1, tvbuf(9,1))
    subtree:add(ctl2, tvbuf(9,1))
    subtree:add(ctl3, tvbuf(9,1))
    subtree:add(cnt, tvbuf(10,1))
    subtree:add(cmd, tvbuf(11,1))
        
    tree:add(fcs     , tvbuf(length-3,2))
    tree:add(stop    , tvbuf(length-1,1))
end

DissectorTable.get("udp.port"):add(default_settings.port, smd)
