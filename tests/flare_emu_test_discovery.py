from __future__ import print_function
import idc
import idaapi
import idautils
import logging
import flare_emu

fixCnt = 2

if __name__ == '__main__':
    # emulate with strict set to false to fix anti-disassembly tricks
    eh = flare_emu.EmuHelper()
    eh.emulateFrom(idc.get_name_ea_simple("_main"),strict=False)
    
    # scan instructions to confirm they were fixed
    start = idc.get_func_attr(idc.here(), idc.FUNCATTR_START)
    end = idc.get_inf_attr(idc.INF_MAX_EA)
    
    addr = start
    fixed = 0
    while addr < end:
        if idc.print_insn_mnem(addr) == "" and idc.print_insn_mnem(addr+1) == "lea":
            fixed += 1
            if fixed == fixCnt:
                break
        addr = idc.next_head(addr, idc.get_inf_attr(idc.INF_MAX_EA))
        
    if fixed == fixCnt:
        print("tests PASSED!")
    else:
        print("tests FAILED!")
        
    