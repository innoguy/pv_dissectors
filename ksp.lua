--[[

    Name         :  ksp.lua
    Author       :  Guy Coen
    Date         :  July 9, 2020
    Company      :  Mind4Energy NV

    Description  

        This is a simple custom Lua dissector for project KSP
        Dissects after pn_io to label setpoints

--]]

local ksp_pn = Proto("KSP-PN","KSP-PN")

local cmd   =   ProtoField.uint8("ksp_pn.cmd",    "Command")
local spt    =  ProtoField.uint16("ksp_pn.spt",   "Setpoint")

ksp_pn.fields = {
    cmd, spt
}



function ksp_pn.dissector(tvbuf, pktinfo, root)

    local pn_io_dissector = Dissector.get("pn_io")
    pn_io_dissector:call(tvbuf, pktinfo, root)

    local tree = root:add(ksp_pn, tvbuf:range(0, 20), "KSP-PN")


    tree:add(cmd, tvbuf(0,1))
    tree:add_le(spt, tvbuf(14,2))     

end

local eth_table = DissectorTable.get("ethertype")
eth_table:add(0x8892, ksp_pn)

