--[[

    Name         :  sungrow.lua
    Author       :  Guy Coen
    Company      :  Mind4Energy NV

    Description  

        This Lua dissector for Wireshark dissects the modbus protocol (TCP port 502) for 
        the following Sungrow inverters:
            SG3125HV-V11
            SG3125HV-MV-V112
            SG3125HV-MV-V113
            SG3400HV
            SG3400HV-MV

    Current limitations
        - Only tested with Wireshark 3.2.5
        - Only tested for Sungrow model SG3125HV-MV-V112
        - Does not differentiate on module, so gives same dissection for
          module 1, module 2 and module 3. This can be checked easily however
          based on the modbus dissector. If it starts with 
            Register 15149 : refers to module 1
            Register 15269 : refers to module 2
            Register 15389 : refers to module 3  
--]]

local sungrow = Proto("ModbusSungrow","Sungrow")

local FCode   =  ProtoField.uint8("sungrow.fcode",   "Function code")
local BCnt    =  ProtoField.uint8("sungrow.bcnt",    "Byte count")
local WCnt    =  ProtoField.uint8("sungrow.wcnt",    "Word count")
local Reg     = ProtoField.uint16("sungrow.reg",     "Modbus Register")
local Ref     = ProtoField.uint16("sungrow.ref",     "Reference")
local Val     = ProtoField.uint16("sungrow.val",     "Setpoint")
local ProtNum = ProtoField.uint16("sungrow.prot_num","Protocol Number")
local ProtVer = ProtoField.string("sungrow.prot_ver","Protocol Version")
local Name1   = ProtoField.string("sungrow.name1",   "Name 1")
local Name2   = ProtoField.string("sungrow.name2",   "Name 2")
local Gap0    =  ProtoField.bytes("sungrow.gap0",    "Gap")
local Curr1   =  ProtoField.int16("sungrow.curr1",   "Current input 1")
local Curr2   =  ProtoField.int16("sungrow.curr2",   "Current input 2")
local Curr3   =  ProtoField.int16("sungrow.curr3",   "Current input 3")
local Curr4   =  ProtoField.int16("sungrow.curr4",   "Current input 4")
local Curr5   =  ProtoField.int16("sungrow.curr5",   "Current input 5")
local Curr6   =  ProtoField.int16("sungrow.curr6",   "Current input 6")
local Curr7   =  ProtoField.int16("sungrow.curr7",   "Current input 7")
local Curr8   =  ProtoField.int16("sungrow.curr8",   "Current input 8")
local Curr9   =  ProtoField.int16("sungrow.curr9",   "Current input 9")
local Curr10  =  ProtoField.int16("sungrow.curr10",   "Current input 10")
local Curr11  =  ProtoField.int16("sungrow.curr11",   "Current input 11")
local Curr12  =  ProtoField.int16("sungrow.curr12",   "Current input 12")
local Curr13  =  ProtoField.int16("sungrow.curr13",   "Current input 13")
local Curr14  =  ProtoField.int16("sungrow.curr14",   "Current input 14")
local Curr15  =  ProtoField.int16("sungrow.curr15",   "Current input 15")
local Curr16  =  ProtoField.int16("sungrow.curr16",   "Current input 16")
local Curr17  =  ProtoField.int16("sungrow.curr17",   "Current input 17")
local Curr18  =  ProtoField.int16("sungrow.curr18",   "Current input 18")
local Curr19  =  ProtoField.int16("sungrow.curr19",   "Current input 19")
local Curr20  =  ProtoField.int16("sungrow.curr20",   "Current input 20")
local Curr21  =  ProtoField.int16("sungrow.curr21",   "Current input 21")
local Curr22  =  ProtoField.int16("sungrow.curr22",   "Current input 22")
local Curr23  =  ProtoField.int16("sungrow.curr23",   "Current input 23")
local Curr24  =  ProtoField.int16("sungrow.curr24",   "Current input 24")
local Curr25  =  ProtoField.int16("sungrow.curr25",   "Current input 25")
local Curr26  =  ProtoField.int16("sungrow.curr26",   "Current input 26")
local Curr27  =  ProtoField.int16("sungrow.curr27",   "Current input 27")
local Curr28  =  ProtoField.int16("sungrow.curr28",   "Current input 28")
local Curr29  =  ProtoField.int16("sungrow.curr29",   "Current input 29")
local Curr30  =  ProtoField.int16("sungrow.curr30",   "Current input 30")
local Curr31  =  ProtoField.int16("sungrow.curr31",   "Current input 31")
local Curr32  =  ProtoField.int16("sungrow.curr32",   "Current input 32")
local Gap1    =  ProtoField.bytes("sungrow.gap1",     "Gap")
local DevTyp  = ProtoField.uint16("sungrow.dev_typ",  "Device type")
local ActPowR = ProtoField.uint16("sungrow.act_pow",  "Active power")
local OutTyp  = ProtoField.uint16("sungrow.out_typ",  "Output type")
local DPowY   = ProtoField.uint32("sungrow.dpowy",    "Daily power yield")
local MPowY   = ProtoField.uint32("sungrow.mpowy",    "Monthly power yield")
local TPowY   = ProtoField.uint32("sungrow.tpowy",    "Total power yield")
local CO2red  = ProtoField.uint32("sungrow.co2red",   "CO2 reduction")
local GrConnM = ProtoField.uint16("sungrow.grconm",   "Grid conection minutes")
local RunHrs  = ProtoField.uint32("sungrow.runhrs",   "Runing hours")
local Gap2    =  ProtoField.bytes("sungrow.gap2",     "Gap")
local ABvolt  = ProtoField.uint16("sungrow.abvolt",   "A-B voltage")
local BCvolt  = ProtoField.uint16("sungrow.bcvolt",   "B-C voltage")
local CAvolt  = ProtoField.uint16("sungrow.cavolt",   "C-A voltage")
local CurrA   = ProtoField.uint16("sungrow.currA",    "Current A")
local CurrB   = ProtoField.uint16("sungrow.currB",    "Current B")
local CurrC   = ProtoField.uint16("sungrow.currC",    "Current C")
local ActPow  = ProtoField.uint32("sungrow.totapow",  "Total active power")
local RctPow  =  ProtoField.int32("sungrow.Qac",      "Total reactive power")
local AppPow  = ProtoField.uint32("sungrow.Pac",      "Total apparent power")
local PF      = ProtoField.uint16("sungrow.PF",       "Power factor")
local Freq    = ProtoField.uint16("sungrow.Freq",     "Grid frequency")
local RctPowR = ProtoField.uint16("sungrow.RctPowR",  "Rated reactive power")
local APLFb   = ProtoField.uint32("sungrow.APLFb",    "Active power limitation feedback")
local RPLFb   =  ProtoField.int32("sungrow.RPLFb",    "Reactive power limitation feedback")
local PFFb    =  ProtoField.int16("sungrow.PFFb",     "Power factor limitation feedback")
local TNS     = ProtoField.uint16("sungrow.TNS",      "Transformer node state")
local APY     = ProtoField.uint32("sungrow.APY",      "Annual power yield")
local OWS     = ProtoField.uint32("sungrow.OWS",      "Overall work state")
local ITmp    =  ProtoField.int16("sungrow.ITmp",    "Internal temperature module")
local DCv     = ProtoField.uint16("sungrow.DCv",     "DC voltage module")
local DCc     = ProtoField.uint16("sungrow.DCc",     "DC current module")
local DCp     = ProtoField.uint32("sungrow.DCp",     "DC power module")
local Effcy   = ProtoField.uint16("sungrow.Effcy",   "Efficiency module")
local STY     = ProtoField.uint16("sungrow.STY",     "State time Year module")
local STM     = ProtoField.uint16("sungrow.STM",     "State time Month module")
local STD     = ProtoField.uint16("sungrow.STD",     "State time Day module")
local STh     = ProtoField.uint16("sungrow.STh",     "State time Hour module")
local STm     = ProtoField.uint16("sungrow.STm",     "State time Minute module")
local STs     = ProtoField.uint16("sungrow.STs",     "State time Second module")
local FS1     = ProtoField.uint32("sungrow.FS1",     "Fault state 1 module")
local FS2     = ProtoField.uint32("sungrow.FS2",     "Fault state 2 module")
local NS1     = ProtoField.uint32("sungrow.NS1",     "Node state 1 module")
local NS2     = ProtoField.uint32("sungrow.NS2",     "Node state 2 module")
local Tmp1    =  ProtoField.int16("sungrow.Tmp1",    "Temperature 1 module")
local Tmp2    =  ProtoField.int16("sungrow.Tmp2",    "Temperature 2 module")
local Tmp3    =  ProtoField.int16("sungrow.Tmp3",    "Temperature 3 module")
local Tmp4    =  ProtoField.int16("sungrow.Tmp4",    "Temperature 4 module")
local Tmp5    =  ProtoField.int16("sungrow.Tmp5",    "Temperature 5 module")
local Tmp6    =  ProtoField.int16("sungrow.Tmp6",    "Temperature 6 module")
local PRg     = ProtoField.uint32("sungrow.PRg",     "Positive resistance to ground module")
local NRg     = ProtoField.uint32("sungrow.NRg",     "Negative resistance to ground module")
local AS      = ProtoField.uint32("sungrow.as",      "Alarm state")
local WS      = ProtoField.uint32("sungrow.ws",      "Work state")
local NVg     =  ProtoField.int16("sungrow.nvg",     "Negative voltage to ground")
local RTmp    =  ProtoField.int16("sungrow.rtmp",    "Radiator temperature")


sungrow.fields = {
    FCode, BCnt, WCnt, Reg, Ref, ProtNum, ProtVer, Name1, Name2, Val,
    Curr1, Curr2, Curr3, Curr4, Curr5, Curr6, Curr7, Curr8, Curr9, Curr10,
    Curr11, Curr12, Curr13, Curr14, Curr15, Curr16, Curr17, Curr18, Curr19, Curr20,
    Curr21, Curr22, Curr23, Curr24, Curr25, Curr26, Curr27, Curr28, Curr29, Curr30,
    Curr31, Curr32,
    Gap0, Gap1, Gap2,
    DevTyp, ActPowR, OutTyp, DPowY, TPowY, MPowY, CO2red, GrConnM, RunHrs,
    ABvolt, BCvolt, CAvolt, CurrA, CurrB, CurrC, 
    ActPow, RctPow, RctPowR, AppPow, PF, Freq, APLFb, RPLFb, PFFb, TNS, APY, OWS,
    ITmp, Tmp1, Tmp2, Tmp3, Tmp4, Tmp5, Tmp6,
    STY, STM, STD, STh, STm, STs,
    DCv, DCc, DCp, PRG, NRG, FS1, FS2, NS1, NS2,
    PRg, NRg, AS, WS, NVg, RTmp, Effcy
}

local modbus_dissector = Dissector.get("mbtcp")

function sungrow.dissector(tvbuf, pktinfo, root)

    local fc  = tvbuf(7,1):uint()
    local bc  = tvbuf(8,1):uint()
    local rg  = tvbuf(8,2):uint()
    local rf  = tvbuf(9,2):uint()

    function hex32_string_to_dec(s)
	    return bit32.lrotate('0x' .. s ,16)
    end

    modbus_dissector:call(tvbuf, pktinfo, root)

    if (fc == 16) then 
        len = tvbuf:range(4,2):uint()
        if (rg == 15011) then
            local tree = root:add(sungrow, tvbuf:range(7, len-1), "ModbusSungrow")
            tree:add(FCode   , tvbuf(7, 1))      -- Modbus function code
            tree:add(Reg     , tvbuf(8, 2))      -- Byte count
            tree:add(WCnt    , tvbuf(10, 2))     -- Byte count
            if (len>=8) then
                tree:add(BCnt    , tvbuf(12, 1))     -- Byte count
                tree:add(Val     , tvbuf(13, 2))     -- Byte count 
            end
        end   
    end

    if ((fc == 4) and (rg >= 14999) and (rg < 15500)) then
        local tree = root:add(sungrow, tvbuf:range(7, 5), "ModbusSungrow")
        tree:add(FCode   , tvbuf(7, 1))     -- Modbus function code
        tree:add(Reg     , tvbuf(8, 2))     -- Byte count
        tree:add(WCnt    , tvbuf(10, 2))     -- Byte count
        --tree:add(BCnt    , tvbuf(12, 1))     -- Byte count
        --tree:add(Val     , tvbuf(13, 2))     -- Byte count    
    end

    if ((fc == 4) and (bc == 236)) then 
        local tree = root:add(sungrow, tvbuf:range(7, 236), "ModbusSungrow")
        tree:add(FCode   , tvbuf(7, 1))         -- Modbus function code
        tree:add(BCnt    , tvbuf(8, 1))         -- Byte count
        tree:add(Ref     , tvbuf(9, 2))         -- 15000
        tree:add(ProtNum , tvbuf(11, 2))        -- 15001
        tree:add(ProtVer , tvbuf(13, 2))        -- 15002
        tree:add(Name1   , tvbuf(15, 18))       -- 15004 .. 15028
        tree:add(Name2   , tvbuf(33, 12))       -- 15004 .. 15028
        -- tree:add(Gap0    , tvbuf(45, 24))  
        tree:add(Curr1   , tvbuf(69, 2))        -- 15030
        tree:add(Curr2   , tvbuf(71, 2))        -- 15031
        tree:add(Curr3   , tvbuf(73, 2))        -- 15032
        tree:add(Curr4   , tvbuf(75, 2))        -- 15033
        tree:add(Curr5   , tvbuf(77, 2))        -- 15034
        tree:add(Curr6   , tvbuf(79, 2))        -- 15035
        tree:add(Curr7   , tvbuf(81, 2))        -- 15036
        tree:add(Curr8   , tvbuf(83, 2))        -- 15037
        tree:add(Curr9   , tvbuf(85, 2))        -- 15038
        tree:add(Curr10  , tvbuf(87, 2))        -- 15039
        tree:add(Curr11  , tvbuf(89, 2))        -- 15040
        tree:add(Curr12  , tvbuf(91, 2))        -- 15041
        tree:add(Curr13  , tvbuf(93, 2))        -- 15042
        tree:add(Curr14  , tvbuf(95, 2))        -- 15043
        tree:add(Curr15  , tvbuf(97, 2))        -- 15044
        tree:add(Curr16  , tvbuf(99, 2))        -- 15045
        tree:add(Curr17  , tvbuf(101, 2))       -- 15046
        tree:add(Curr18  , tvbuf(103, 2))       -- 15047
        tree:add(Curr19  , tvbuf(105, 2))       -- 15048
        tree:add(Curr20  , tvbuf(107, 2))       -- 15049
        tree:add(Curr21  , tvbuf(109, 2))       -- 15050
        tree:add(Curr22  , tvbuf(111, 2))       -- 15051
        tree:add(Curr23  , tvbuf(113, 2))       -- 15052
        tree:add(Curr24  , tvbuf(115, 2))       -- 15053
        tree:add(Curr25  , tvbuf(117, 2))       -- 15054
        tree:add(Curr26  , tvbuf(119, 2))       -- 15055
        tree:add(Curr27  , tvbuf(121, 2))       -- 15056
        tree:add(Curr28  , tvbuf(123, 2))       -- 15057
        tree:add(Curr29  , tvbuf(125, 2))       -- 15058
        tree:add(Curr30  , tvbuf(127, 2))       -- 15059
        tree:add(Curr31  , tvbuf(129, 2))       -- 15060
        tree:add(Curr32  , tvbuf(131, 2))       -- 15061
        -- tree:add(Gap1    , tvbuf(133, 16))  
        tree:add(DevTyp  , tvbuf(149, 2))       -- 15070
        tree:add(ActPowR , tvbuf(151, 2))       -- 15071
        tree:add(OutTyp  , tvbuf(153, 2))       -- 15072
        num = hex32_string_to_dec(tvbuf(155,4))
        tree:add(DPowY   , tvbuf(155, 4), num)  -- 15073
        num = hex32_string_to_dec(tvbuf(159,4))
        tree:add(MPowY   , tvbuf(159, 4), num)  -- 15075
        num = hex32_string_to_dec(tvbuf(163,4))
        tree:add(TPowY   , tvbuf(163, 4), num)  -- 15077
        num = hex32_string_to_dec(tvbuf(167,4))
        tree:add(CO2red  , tvbuf(167, 4), num)  -- 15079
        tree:add(GrConnM , tvbuf(171, 2))       -- 15081
        num = hex32_string_to_dec(tvbuf(173,4))
        tree:add(RunHrs  , tvbuf(173, 4), num)   -- 15082
        -- tree:add(Gap2    , tvbuf(177, 16))  
        num = hex32_string_to_dec(tvbuf(193,4))
        tree:add(DCp     , tvbuf(193, 4), num)   -- 15092
        tree:add(ABvolt  , tvbuf(197, 2))        -- 15094
        tree:add(BCvolt  , tvbuf(199, 2))        -- 15095
        tree:add(CAvolt  , tvbuf(201, 2))        -- 15096
        tree:add(CurrA   , tvbuf(203, 2))        -- 15097
        tree:add(CurrB   , tvbuf(205, 2))        -- 15098
        tree:add(CurrC   , tvbuf(207, 2))        -- 15099
        num = hex32_string_to_dec(tvbuf(209,4))
        tree:add(ActPow  , tvbuf(209, 4), num)   -- 15100
        num = hex32_string_to_dec(tvbuf(213,4))
        tree:add(RctPow  , tvbuf(213, 4), num)   -- 15102
        num = hex32_string_to_dec(tvbuf(217,4))
        tree:add(AppPow  , tvbuf(217, 4), num)   -- 15104
        tree:add(PF      , tvbuf(221, 2))        -- 15106
        tree:add(Freq    , tvbuf(223, 2))        -- 15107
        tree:add(RctPowR , tvbuf(225, 2))        -- 15108
        num = hex32_string_to_dec(tvbuf(227,4))
        tree:add(APLFb   , tvbuf(227, 4),num)    -- 15109
        num = hex32_string_to_dec(tvbuf(231,4))
        tree:add(RPLFb   , tvbuf(231, 4),num)    -- 15110
        tree:add(PFFb    , tvbuf(235, 2))        -- 15111
        tree:add(TNS     , tvbuf(237, 2))        -- 15112
        num = hex32_string_to_dec(tvbuf(239,4))
        tree:add(APY     , tvbuf(239, 4),num)    -- 15113
        tree:add(OWS     , tvbuf(243, 2))        -- 15114
    end

    if ((fc == 4) and (bc == 136)) then 
        local tree = root:add(sungrow, tvbuf:range(5, 136), "ModbusSungrow")
        num = hex32_string_to_dec(tvbuf(9,4))
        tree:add(DPowY   , tvbuf(9, 4),num)     -- 15150
        num = hex32_string_to_dec(tvbuf(13,4))
        tree:add(MPowY   , tvbuf(13, 4),num)    -- 15152
        num = hex32_string_to_dec(tvbuf(17,4))
        tree:add(TPowY   , tvbuf(17, 4),num)    -- 15154
        tree:add(GrConnM , tvbuf(21, 2))        -- 15156
        num = hex32_string_to_dec(tvbuf(23,4))
        tree:add(RunHrs  , tvbuf(23, 4),num)    -- 15157
        tree:add(ITmp    , tvbuf(27, 2))        -- 15159
        tree:add(DCv     , tvbuf(29, 2))        -- 15160
        tree:add(DCc     , tvbuf(31, 2))        -- 15161
        num = hex32_string_to_dec(tvbuf(33,4))
        tree:add(DCp     , tvbuf(33, 4),num)    -- 15162
        tree:add(ABvolt  , tvbuf(37, 2))        -- 15164
        tree:add(BCvolt  , tvbuf(39, 2))        -- 15165
        tree:add(CAvolt  , tvbuf(41, 2))        -- 15166
        tree:add(CurrA   , tvbuf(43, 2))        -- 15167
        tree:add(CurrB   , tvbuf(45, 2))        -- 15168
        tree:add(CurrC   , tvbuf(47, 2))        -- 15169
        num = hex32_string_to_dec(tvbuf(49,4))
        tree:add(ActPow  , tvbuf(49, 4), num)   -- 15170
        num = hex32_string_to_dec(tvbuf(53,4))
        tree:add(RctPow  , tvbuf(53, 4), num)   -- 15172
        tree:add(PF      , tvbuf(57, 2))        -- 15174
        tree:add(Freq    , tvbuf(59, 2))        -- 15175
        --num = hex32_string_to_dec(tvbuf(61,4))
        tree:add(Effcy   , tvbuf(61, 2))        -- 15176
        tree:add(STY     , tvbuf(65, 2))        -- 15178
        tree:add(STM     , tvbuf(67, 2))        -- 15179
        tree:add(STD     , tvbuf(69, 2))        -- 15180
        tree:add(STh     , tvbuf(71, 2))        -- 15181
        tree:add(STm     , tvbuf(73, 2))        -- 15182
        tree:add(STs     , tvbuf(75, 2))        -- 15183
        -- tree:add(Gap0    , tvbuf(77, 2))        -- 15184
        tree:add(RctPowR , tvbuf(79, 2))        -- 15185
        num = hex32_string_to_dec(tvbuf(81,4))
        tree:add(FS1     , tvbuf(81, 4),num)    -- 15186
        num = hex32_string_to_dec(tvbuf(85,4))
        tree:add(FS2     , tvbuf(85, 4),num)    -- 15188
        -- tree:add(Gap1    , tvbuf(89, 8))    -- 15190
        num = hex32_string_to_dec(tvbuf(97,4))
        tree:add(NS1     , tvbuf(97, 4),num)    -- 15194
        num = hex32_string_to_dec(tvbuf(101,4))
        tree:add(NS2     , tvbuf(101, 4),num)   -- 15196
        tree:add(Tmp1    , tvbuf(105, 2))       -- 15198
        tree:add(Tmp2    , tvbuf(107, 2))       -- 15199
        tree:add(Tmp3    , tvbuf(109, 2))       -- 15200
        tree:add(Tmp4    , tvbuf(111, 2))       -- 15201
        tree:add(Tmp5    , tvbuf(113, 2))       -- 15202
        tree:add(Tmp6    , tvbuf(115, 2))       -- 15203
        num = hex32_string_to_dec(tvbuf(117,4))
        tree:add(PRg     , tvbuf(117, 4),num)   -- 15204
        num = hex32_string_to_dec(tvbuf(121,4))
        tree:add(NRg     , tvbuf(121, 4),num)   -- 15206
        num = hex32_string_to_dec(tvbuf(125,4))
        tree:add(WS      , tvbuf(125, 4),num)   -- 15208
        num = hex32_string_to_dec(tvbuf(129,4))
        tree:add(AS      , tvbuf(129, 4),num)   -- 15210
        tree:add(NVg     , tvbuf(133, 2))       -- 15212
        num = hex32_string_to_dec(tvbuf(135,4))
        tree:add(APY     , tvbuf(135, 4),num)   -- 15213
        num = hex32_string_to_dec(tvbuf(139,4))
        tree:add(CO2red  , tvbuf(139, 4),num)   -- 15215
        tree:add(RTmp    , tvbuf(143, 2))       -- 15217
    end
end

local tcp_table = DissectorTable.get("tcp.port")
tcp_table:add(502, sungrow)

