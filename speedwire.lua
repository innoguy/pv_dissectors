local debug_level = {
    DISABLED = 0,
    LEVEL_1  = 1,
    LEVEL_2  = 2
}

local DEBUG = debug_level.LEVEL_1

local default_settings =
{
    debug_level  = DEBUG,
    port         = 9522,
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

local spw = Proto("spw","SMA Speedwire Protocol")

local header = ProtoField.new("spw.header", "spw.header" ,ftypes.STRING)
local magic1 = ProtoField.new("spw.magic1", "spw.magic1", ftypes.UINT32, nil, base.HEX)
local unknw2 = ProtoField.new("spw.unknown2", "spw.unknown2", ftypes.UINT32, nil, base.HEX)
local plen   = ProtoField.new("spw.plen" , "spw.plen",    ftypes.UINT16)
local magic2 = ProtoField.new("spw.magic2", "spw.magic2", ftypes.UINT32, nil, base.HEX)
local len4   = ProtoField.new("spw.len4",  "spw.len4",    ftypes.UINT8)

local ctrl_types = {
    [0x00] = "Network Inquiry Non-blocking",
    [0x10] = "Network Inquiry Blocking",
    [0x40] = "Network Response Non-blocking",
    [0x50] = "Network Respose Blocking" ,
    [0x80] = "Group Inquiry Non-blocking" ,
    [0x90] = "Group Inquiry Blocking" ,
    [0xc0] = "Group Response Non-blocking" ,
    [0xd0] = "Group Response Blocking"
}

local ctrl   = ProtoField.new("spw.ctrl", "spw.ctrl",     ftypes.UINT8, ctrl_types, base.HEX, 0xff)
local susyID = ProtoField.new("spw.susyID", "spw.susyID", ftypes.UINT32, nil, base.HEX)
local serial = ProtoField.new("spw.serial", "spw.serial", ftypes.UINT32)
local sessID = ProtoField.new("spw.sessID", "spw.sessID", ftypes.UINT32)

local obis   = ProtoField.new("spw.obis", "spw.obis",     ftypes.BYTES)

local dp01    = ProtoField.new("spw.dp01", "spw.dp01",    ftypes.BYTES)
local dp02    = ProtoField.new("spw.dp02", "spw.dp02",    ftypes.BYTES)
local dp03    = ProtoField.new("spw.dp03", "spw.dp03",    ftypes.BYTES)
local dp04    = ProtoField.new("spw.dp04", "spw.dp04",    ftypes.BYTES)
local dp05    = ProtoField.new("spw.dp05", "spw.dp05",    ftypes.BYTES)
local dp06    = ProtoField.new("spw.dp06", "spw.dp06",    ftypes.BYTES)
local dp07    = ProtoField.new("spw.dp07", "spw.dp07",    ftypes.BYTES)
local dp08    = ProtoField.new("spw.dp08", "spw.dp08",    ftypes.BYTES)
local dp09    = ProtoField.new("spw.dp09", "spw.dp09",    ftypes.BYTES)
local dp10    = ProtoField.new("spw.dp10", "spw.dp10",    ftypes.BYTES)
local dp11    = ProtoField.new("spw.dp11", "spw.dp11",    ftypes.BYTES)
local dp12    = ProtoField.new("spw.dp12", "spw.dp12",    ftypes.BYTES)
local dp13    = ProtoField.new("spw.dp13", "spw.dp13",    ftypes.BYTES)
local dp14    = ProtoField.new("spw.dp14", "spw.dp14",    ftypes.BYTES)
local dp15    = ProtoField.new("spw.dp15", "spw.dp15",    ftypes.BYTES)
local dp16    = ProtoField.new("spw.dp16", "spw.dp16",    ftypes.BYTES)
local dp17    = ProtoField.new("spw.dp17", "spw.dp17",    ftypes.BYTES)
local dp18    = ProtoField.new("spw.dp18", "spw.dp18",    ftypes.BYTES)
local dp19    = ProtoField.new("spw.dp19", "spw.dp19",    ftypes.BYTES)
local dp20    = ProtoField.new("spw.dp20", "spw.dp20",    ftypes.BYTES)
local dp21    = ProtoField.new("spw.dp21", "spw.dp21",    ftypes.BYTES)
 
local str1    = ProtoField.new("spw.str1", "spw.str1" ,	ftypes.STRING)

local cmd_table = {
    [0x6a02020e] = "Curtail active power to value in dp10"
}
local cmd    = ProtoField.new("spw.cmd", "spw.cmd",    ftypes.UINT32, cmd_table, base.HEX)

local cmd_flag1  =  ProtoField.new("spw.cmd.flag1", "spw.cmd.flag1", ftypes.UINT32, nil, base.HEX, 0xf0000000)
local cmd_flag2_list = {
    [0x0] = "Request",
    [0x1] = "Response"
}
local cmd_flag2  =  ProtoField.new("spw.cmd.flag2", "spw.cmd.flag2", ftypes.UINT32, cmd_flag2_list, base.HEX, 0x0f000000)
local cmd_flag3  =  ProtoField.new("spw.cmd.flag3", "spw.cmd.flag3", ftypes.UINT32, nil, base.HEX, 0x00f00000)
local cmd_flag4  =  ProtoField.new("spw.cmd.flag4", "spw.cmd.flag4", ftypes.UINT32, nil, base.HEX, 0x000f0000)
local cmd_flag5  =  ProtoField.new("spw.cmd.flag5", "spw.cmd.flag5", ftypes.UINT32, nil, base.HEX, 0x0000f000)
local cmd_flag6  =  ProtoField.new("spw.cmd.flag6", "spw.cmd.flag6", ftypes.UINT32, nil, base.HEX, 0x00000f00)
local cmd_flag7  =  ProtoField.new("spw.cmd.flag7", "spw.cmd.flag7", ftypes.UINT32, nil, base.HEX, 0x000000f0)
local cmd_flag8  =  ProtoField.new("spw.cmd.flag8", "spw.cmd.flag8", ftypes.UINT32, nil, base.HEX, 0x0000000f)

local val1    = ProtoField.new("spw.val1", "spw.val1", ftypes.UINT32)
local val2    = ProtoField.new("spw.val2", "spw.val2", ftypes.UINT32)
local val3    = ProtoField.new("spw.val3", "spw.val3", ftypes.UINT32)
local val4    = ProtoField.new("spw.val4", "spw.val4", ftypes.UINT32)

local hex1    = ProtoField.new("spw.hex1", "spw.hex1", ftypes.BYTES)

local tstamp  = ProtoField.new("spw.tstamp", "spw.tstamp", ftypes.UINT32, nil, base.DEC)

local lritable = {
		[0x2148] = "OperationHealth / INV_STATUS",
		[0x2377] = "CoolsysTmpNom / Operating condition temperatures",
        [0x251e] = "MeteringTotOpTms / SPOT_PDC1_2",
        [0x2601] = "MeteringTotWhOut / SPOT_ETOTAL",
        [0x2622] = "MeteringDyWhOut  / SPOT_ETODAY",
        [0x263F] = "GridMsTotW / SPOT_PACTOT",
        [0x295A] = "BatChaStt / Current battery charge status",
        [0x411E] = "OperationHealthSttOk  / Nominal power in Ok Mode (aka INV_PACMAX1)",
        [0x411F] = "OperationHealthSttWrn / Nominal power in Warning Mode (aka INV_PACMAX2)",
        [0x4120] = "OperationHealthSttAlm / Nominal power in Fault Mode (aka INV_PACMAX3)",
        [0x4164] = "OperationGriSwStt / INV_GRIDRELAY",
        [0x4166] = "OperationRmgTms / Waiting time until feed-in",
        [0x451f] = "DcMsVol / SPOT_UDC1_2",
        [0x4521] = "DcMsAmp / SPOT_IDC1_2",
        [0x4623] = "MeteringPvMsTotWhOut / PV generation counter reading",
        [0x4624] = "MeteringGridMsTotWhOut / Grid feed-in counter reading",
        [0x4625] = "MeteringGridMsTotWhIn  / Grid reference counter reading",
        [0x4626] = "MeteringCsmpTotWhIn.   / Meter reading consumption meter",
        [0x4627] = "MeteringGridMsDyWhOut",
        [0x4628] = "MeteringGridMsDyWhIn",
        [0x462E] = "MeteringTotOpTms / SPOT_OPERTM",
        [0x462F] = "MeteringTotFeedTms / SPOT_FEEDTM",
        [0x4631] = "MeteringGriFailTms / Power outage",
        [0x463A] = "MeteringWhIn / Absorbed energy",
        [0x463B] = "MeteringWhOut / Released energy",
        [0x4635] = "MeteringPvMsTotWOut / PV power generated",
        [0x4636] = "MeteringGridMsTotWOut / Power grid feed-in",
        [0x4637] = "MeteringGridMsTotWIn / Power grid reference",
        [0x4639] = "MeteringCsmpTotWIn / Consumer power",
        [0x4640] = "GridMsWphsA / Power L1 (aka SPOT_PAC1)",
        [0x4641] = "GridMsWphsB / Power L2 (aka SPOT_PAC2)",
        [0x4642] = "GridMsWphsC / Power L3 (aka SPOT_PAC3)",
      	[0x4648] = "GridMsPhVphsA / Grid voltage phase L1 (aka SPOT_UAC1)",
      	[0x4649] = "GridMsPhVphsB / Grid voltage phase L2 (aka SPOT_UAC2)",
      	[0x464A] = "GridMsPhVphsC / Grid voltage phase L3 (aka SPOT_UAC3)",
        [0x4650] = "GridMsAphsA_1 / Grid current phase L1 (aka SPOT_IAC1)",
        [0x4651] = "GridMsAphsB_1 / Grid current phase L2 (aka SPOT_IAC2)",
        [0x4652] = "GridMsAphsC_1 / Grid current phase L3 (aka SPOT_IAC3)",
      	[0x4653] = "GridMsAphsA / Grid current phase L1 (aka SPOT_IAC1_2)",
        [0x4654] = "GridMsAphsB / Grid current phase L2 (aka SPOT_IAC1_2)",        
        [0x4655] = "GridMsAphsC / Grid current phase L3 (aka SPOT_IAC1_2)",
        [0x4657] = "GridMsHz / Grid frequency (aka SPOT_FREQ)",
      	[0x46AA] = "MeteringSelfCsmpSelfCsmpWh / Energy consumed internally",
        [0x46AB] = "MeteringSelfCsmpActlSelfCsmp / Current self-consumption",        
        [0x46AC] = "MeteringSelfCsmpSelfCsmpInc / Current rise in self-consumption",
        [0x46AD] = "MeteringSelfCsmpAbsSelfCsmpInc / Rise in self-consumption",
      	[0x46AE] = "MeteringSelfCsmpDySelfCsmpInc / Rise in self-consumption today",
        [0x491E] = "BatDiagCapacThrpCnt / Number of battery charge throughputs",        
        [0x4926] = "BatDiagTotAhIn / Amp hours counter for battery charge",
        [0x4927] = "BatDiagTotAhOut / Amp hours counter for battery discharge",
      	[0x495B] = "BatTmpVal / Battery temperature",
        [0x495C] = "BatVol / Battery voltage",
        [0x495D] = "BatAmp / Battery current",
        [0x821E] = "NameplateLocation / INV_NAME",
      	[0x821F] = "NameplateMainModel / INV_CLASS",
        [0x8220] = "NameplateModel / INV_TYPE",        
        [0x8221] = "NameplateAvalGrpUsr",
        [0x8234] = "NameplatePkgRev / INV_SWVER",
      	[0x832A] = "InverterWLim / INV_PACMAX1_2 (max active power)",
        [0x464B] = "GridMsPhVphsA2B6100",        
        [0x464C] = "GridMsPhVphsB2C6100",
        [0x464D] = "GridMsPhVphsC2A6100"
}

local lridef      = ProtoField.new("spw.lridef", "spw.lridef",      ftypes.UINT32, lritable, base.HEX, 0x00ffff00)


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

local obis_src    = ProtoField.new("spw.obis.src", "spw.obis.src",	ftypes.UINT16, nil, base.HEX, 0xffff)
local obis_dst    = ProtoField.new("spw.obis.dst", "spw.obis.dst",	ftypes.UINT16, nil, base.HEX, 0xffff)
local obis_ctl    = ProtoField.new("spw.obis.ctl", "spw.obis.ctl",	ftypes.UINT8,  nil, base.HEX, 0xf0)
local obis_cnt    = ProtoField.new("spw.obis.cnt", "spw.obis.cnt",	ftypes.UINT8,  nil, base.DEC)
local obis_cmd    = ProtoField.new("spw.obis.cmd", "spw.obis.cmd",	ftypes.UINT8,  nil, base.DEC)
local obis_dta    = ProtoField.new("spw.obis.dta", "spw.obis.dta",	ftypes.BYTES)

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

spw.prefs.debug = Pref.enum("Debug", default_settings.debug_level,
                            "The debug printing level", debug_pref_enum)

spw.prefs.port  = Pref.uint("Port number", default_settings.port,
                            "The UDP port number for Speedwire")

spw.prefs.heur  = Pref.bool("Heuristic enabled", default_settings.heur_enabled,
                            "Whether heuristic dissection is enabled or not")

----------------------------------------
-- a function for handling prefs being changed
function spw.prefs_changed()
    dprint2("prefs_changed called")

    default_settings.debug_level  = spw.prefs.debug
    reset_debug_level()

    default_settings.heur_enabled = spw.prefs.heur

    if default_settings.port ~= spw.prefs.port then
        -- remove old one, if not 0
        if default_settings.port ~= 0 then
            dprint2("removing Speedwire from port",default_settings.port)
            DissectorTable.get("udp.port"):remove(default_settings.port, spw)
        end
        -- set our new default
        default_settings.port = spw.prefs.port
        -- add new one, if not 0
        if default_settings.port ~= 0 then
            dprint2("adding Speedwire to port",default_settings.port)
            DissectorTable.get("udp.port"):add(default_settings.port, spw)
        end
    end

end

dprint2("Speedwire Prefs registered")

spw.fields = {header, magic1, unknw2, plen, magic2, len4, ctrl, susyID, sessID, serial,
	obis, obis_src, obis_dst, obis_ctl, obis_cnt, obis_cmd, obis_dta, tstamp,
    dp01, dp02, dp03, dp04, dp05, dp06, dp07, dp08, dp09, dp10, dp11, dp12, dp13, dp14, dp15, dp16,
    dp17, dp18, dp19, dp20, dp21, cmd,
    lridef, val1, val2, val3, val4, str1, hex1,
    cmd_flag1, cmd_flag2, cmd_flag3, cmd_flag4, cmd_flag5, cmd_flag6, cmd_flag7, cmd_flag8
}

----------------------------------------
-- create some expert info fields (this is new functionality in 1.11.3)
-- Expert info fields are very similar to proto fields: they're tied to our protocol,
-- they're created in a similar way, and registered by setting a 'experts' field to
-- a table of them just as proto fields were put into the 'dns.fields' above
-- The old way of creating expert info was to just add it to the tree, but that
-- didn't let the expert info be filterable in wireshark, whereas this way does
local ef_query     = ProtoExpert.new("spw.query.expert", "Speedwire query message",
                                     expert.group.REQUEST_CODE, expert.severity.CHAT)
local ef_response  = ProtoExpert.new("spw.response.expert", "Speedwire response message",
                                     expert.group.RESPONSE_CODE, expert.severity.CHAT)
local ef_ultimate  = ProtoExpert.new("spw.response.ultimate.expert", "Speedwire answer to life, the universe, and everything",
                                     expert.group.COMMENTS_GROUP, expert.severity.NOTE)
-- some error expert info's
local ef_too_short = ProtoExpert.new("spw.too_short.expert", "Speedwire message too short",
                                     expert.group.MALFORMED, expert.severity.ERROR)
local ef_bad_query = ProtoExpert.new("spw.query.missing.expert", "Speedwire query missing or malformed",
                                     expert.group.MALFORMED, expert.severity.WARN)

-- register them
spw.experts = { ef_query, ef_too_short, ef_bad_query, ef_response, ef_ultimate }

function spw.dissector(tvbuf, pktinfo, root)
	length = tvbuf:len()

	if length == 0 then return end
    pktinfo.cols.protocol:set("SPEEDWIRE")
    local pktlen = tvbuf:reported_length_remaining()
    local tree    = root:add(spw, tvbuf:range(0, pktlen), "Speedwire Data")
    local subtree = tree:add(spw, tvbuf:range(0, pktlen), "Command")

    tree:add(header , tvbuf(0,4))
    tree:add(magic1 , tvbuf(4,4))
    tree:add(unknw2 , tvbuf(8,4))
    local plength = tvbuf:range(12,2):uint()
    tree:add(plen,    tvbuf(12,2))
    local code1 = tvbuf:range(8,4):uint()
    if (code1 == 4294967295) then
    	tree:add_proto_expert_info(ef_response, "SMA device discovery")
    elseif (code1 == 1) then
    	if (plength == 2) then
            local code3 = tvbuf:range(14,4):uint()
	    	if (code3 == 1) then
	    		tree:add_proto_expert_info(ef_response, "SMA device response")
	    	else
	    		tree:add_proto_expert_info(ef_response, "Not yet implemented")
	    	end
	    elseif (plength > 2) then
            tree:add(magic2,  tvbuf(14,4))   -- 00 10 60 65
            tree:add_le(susyID, tvbuf(18,4))
	    	-- tree:add(len4  ,  tvbuf(18,1))   -- packet length / 4
	    	-- tree:add(ctrl   , tvbuf(19,1))   -- control
	    	-- local ctl = string.format("%X",tvbuf(19,1):uint())
	    	-- tree:add_le(susyID , tvbuf(20,2))
	    	local sid = tvbuf:range(18,4):uint()
            str = string.format("%08X",sid):sub(3,8)
            print(str)
		    if (str == "A0B500" or str == "F0B500") then
		    	tree:add_le(serial, tvbuf(22,4)) 
		    	tree:add_le(dp01,   tvbuf(26,4))
		    	tree:add_le(dp02,   tvbuf(30,4))
		    	tree:add_le(dp03,   tvbuf(34,4))
		    	tree:add_le(tstamp, tvbuf(38,4))
                tree:add_le(cmd,   tvbuf(42,4))
                subtree:add(cmd_flag1, tvbuf(42,4))
                subtree:add(cmd_flag2, tvbuf(42,4))
                subtree:add(cmd_flag3, tvbuf(42,4))
                subtree:add(cmd_flag4, tvbuf(42,4))
                subtree:add(cmd_flag5, tvbuf(42,4))
                subtree:add(cmd_flag6, tvbuf(42,4))
                subtree:add(cmd_flag7, tvbuf(42,4))
                subtree:add(cmd_flag8, tvbuf(42,4))
		    	tree:add_le(lridef,   tvbuf(46,4))
		    	if (plength > 30) then
		    		tree:add_le(dp06,   tvbuf(50,4))
		    		tree:add_le(dp07,   tvbuf(54,4))
		    	end
		    	if (plength >= 70) then
		    		tree:add_le(dp08,   tvbuf(54,4))
		    		tree:add_le(dp09,   tvbuf(58,4))
		    		tree:add_le(dp10,   tvbuf(62,4))
		    		tree:add_le(dp11,   tvbuf(66,4))
		    		tree:add_le(dp12,   tvbuf(70,4))
		    		tree:add_le(dp13,   tvbuf(74,4))
		    		tree:add_le(dp14,   tvbuf(78,4))
		    		tree:add_le(dp15,   tvbuf(82,4))
		    		tree:add_le(dp16,   tvbuf(86,4))
		    	end
		    elseif (str == "907D00" or str == "D07D00") then
		    	tree:add_le(sessID, tvbuf(22,4))
		    	tree:add_le(dp01  , tvbuf(26,4))
		    	tree:add_le(serial, tvbuf(30,4))
		    	tree:add_le(dp02  , tvbuf(34,4))
		    	tree:add_le(dp03  , tvbuf(38,4))
                tree:add_le(cmd  , tvbuf(42,4))
                subtree:add(cmd_flag1, tvbuf(42,4))
                subtree:add(cmd_flag2, tvbuf(42,4))
                subtree:add(cmd_flag3, tvbuf(42,4))
                subtree:add(cmd_flag4, tvbuf(42,4))
                subtree:add(cmd_flag5, tvbuf(42,4))
                subtree:add(cmd_flag6, tvbuf(42,4))
                subtree:add(cmd_flag7, tvbuf(42,4))
                subtree:add(cmd_flag8, tvbuf(42,4))
		    	tree:add_le(dp05  , tvbuf(46,4))
		    	tree:add_le(dp06  , tvbuf(50,4))
		    	tree:add_le(lridef, tvbuf(54,4))
		    	tree:add_le(dp07  , tvbuf(58,4))
		    	local ldn = tvbuf:range(54,4):uint()
		    	local lds = string.format("%08X",ldn)
		    	mask = 0x00ffff00
		    	x = bit.band(ldn,mask)
		    	data_type = bit.band(ldn,0xff)
		    	if (data_type == 0) then
		    		tree:add_le(val1, tvbuf(62,4))
		    		tree:add_le(val2, tvbuf(66,4))
		    		tree:add_le(val3, tvbuf(70,4))
		    		tree:add_le(val4, tvbuf(74,4))
		    		tree:add(hex1, tvbuf(78,4))
		    	elseif (data_type == 8) then
		    		tree:add_le(val1, tvbuf(62,4))
		    		tree:add_le(val2, tvbuf(66,4))
		    		tree:add_le(val3, tvbuf(70,4))
		    		tree:add_le(val4, tvbuf(74,4))
		    	elseif (data_type == 16) then
		    		tree:add_le(str1, tvbuf(62,16))
		    	elseif (data_type == 64) then
		    		tree:add_le(val1, tvbuf(62,4))
		    		tree:add_le(val2, tvbuf(66,4))
		    		tree:add_le(val3, tvbuf(70,4))
		    		tree:add_le(val4, tvbuf(74,4))
		    	end
                local xs = string.format("%08X",x)
            elseif ((str == "A0FF00") or (str == "90FDFF")) then
                tree:add_le(dp01  , tvbuf(22,4))
		    	tree:add_le(dp02  , tvbuf(26,4))
		    	tree:add_le(serial  , tvbuf(30,4))
		    	tree:add_le(dp04  , tvbuf(34,4))
		    	tree:add_le(dp05  , tvbuf(38,4))   -- Looks like counter / timer for 192.168.10.19 to 239.12.255.253
		    	tree:add_le(dp06  , tvbuf(42,4))
		    	tree:add_le(dp07  , tvbuf(46,4))
                tree:add_le(dp08  , tvbuf(50,4))
                tree:add_le(dp09  , tvbuf(54,4))
                tree:add_le(dp10  , tvbuf(58,4))
                tree:add_le(dp11  , tvbuf(62,4))
                tree:add_le(dp12  , tvbuf(66,4))
                tree:add_le(serial  , tvbuf(70,4))
                tree:add_le(dp14  , tvbuf(74,4))
                tree:add_le(dp15  , tvbuf(78,4))
                tree:add_le(dp16  , tvbuf(82,4))
                tree:add_le(dp17  , tvbuf(86,4))
                tree:add_le(dp18  , tvbuf(90,4))
                tree:add_le(dp19  , tvbuf(94,4))
            else
                tree:add_le(dp01  , tvbuf(22,4))
		    	tree:add_le(dp02  , tvbuf(26,4))
		    	tree:add_le(dp03  , tvbuf(30,4))
		    	tree:add_le(dp04  , tvbuf(34,4))
                tree:add_le(dp05  , tvbuf(38,4))
                tree:add_le(dp06  , tvbuf(42,4))
		    	tree:add_le(dp07  , tvbuf(46,4))
		    end
		end
	end
end

DissectorTable.get("udp.port"):add(9522, spw)
