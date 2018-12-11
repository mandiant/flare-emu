############################################
# Copyright (C) 2018 FireEye, Inc.
#
# Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
# http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-BSD-3-CLAUSE or
# https://opensource.org/licenses/BSD-3-Clause>, at your option. This file may not be
# copied, modified, or distributed except according to those terms.
#
# Author: James T. Bennett
#
# flare_emu_test.py is an IDApython script for testing flare-emu
#
# Dependencies:
# https://github.com/fireeye/flare-emu
############################################

from __future__ import print_function
import idc
import idaapi
import idautils
import flare_emu

testStrings = ["HELLO", "GOODBYE", "TEST"]

def decode(argv):
    myEH = flare_emu.EmuHelper()
    print("testing emulateRange feature for _xorCrypt function")
    mu = myEH.emulateRange(idc.get_name_ea_simple("_xorCrypt"), registers = {"arg1":argv[0], "arg2":argv[1], 
                           "arg3":argv[2], "arg4":argv[3]})
    return myEH.getEmuString(argv[0])
    
def ch(address, argv, funcName, userData):
    eh = userData["EmuHelper"]
    if funcName == "_xorCrypt":
        s = eh.getEmuString(argv[0])
        dec = decode(argv)
        if dec not in testStrings:
            print("FAILED: incorrect decoded string @ %016X" % address)
        else:
            print("emulateRange xorCrypt passed")
    
def iterateHook(eh, address, argv, userData):
    fmtStr = eh.getEmuString(argv[0])
    if fmtStr[0] != "%" or fmtStr[-1:] != "\n":
        print("FAILED: printf getting wrong arguments @ %016X" % address)
    else:
        print("printf test passed")
    
    
    
if __name__ == '__main__':   
    eh = flare_emu.EmuHelper()
    print("testing iterate feature for printf function")
    eh.iterate(idc.get_name_ea_simple("_printf"), iterateHook, callHook = ch)