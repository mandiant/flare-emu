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
# flare_emu_test_hooks.py is a script for testing flare-emu with IDA Pro and Radare2
#
# Dependencies:
# https://github.com/fireeye/flare-emu
############################################

from __future__ import print_function
import flare_emu
import sys
import logging

from unicorn import UC_ARCH_X86, UC_MEM_READ, UC_MEM_WRITE

testStrings = ["HELLO", "GOODBYE", "TEST"]

def decode(argv):
    if len(sys.argv) == 3:
        myEH = flare_emu.EmuHelper(samplePath=sys.argv[1], isRizin=True)
    elif len(sys.argv) == 2:
        myEH = flare_emu.EmuHelper(samplePath=sys.argv[1])
    else:
        myEH = flare_emu.EmuHelper()
    print("testing emulateRange feature for _xorCrypt function")
    myEH.emulateRange(myEH.analysisHelper.getNameAddr("_xorCrypt"), registers = {"arg1":argv[0], "arg2":argv[1], 
                           "arg3":argv[2], "arg4":argv[3]})
    return myEH.getEmuString(argv[0]).decode("latin1")
    
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
    fmtStr = eh.getEmuString(argv[0]).decode("latin1")
    if fmtStr[0] != "%" or fmtStr[-1:] != "\n":
        print("FAILED: printf getting wrong arguments @ %016X" % address)
    else:
        print("printf test passed")


def test_memory_access_hook(eh):
    """ Compare memory access identified in IDA and hooked instructions. """
    print("\ntesting memory access hook")
    main_va = eh.analysisHelper.getNameAddr("_main")
    userData = dict()
    userData["mov_types_hook"] = dict()
    eh.emulateRange(main_va, memAccessHook=get_mov_types_hook, hookData=userData)
    if get_mov_types(eh, main_va) != userData["mov_types_hook"]:
        print("FAILED: memory access hook test. Memory access identified in binary analysis and hooked instructions differ.")
    else:
        print("memory access hook test passed")


def get_mov_types_hook(uc, access, address, size, value, userData):
    """
    Return dictionary that maps addresses of all hooked mov instructions that read or write memory, other memory access
    types are ignored
    """
    eh = userData["EmuHelper"]
    pc = eh.getRegVal("pc")
    if eh.analysisHelper.getMnem(pc).lower() != "mov":
        # ignore other instructions
        return
    if access in [UC_MEM_READ, UC_MEM_WRITE]:
        userData["mov_types_hook"][pc] = access


def get_mov_types(eh, va):
    """
    Return dictionary that maps the addresses of all mov instructions for a function that read or write memory,
    mov instruction without memory access are ignored
    :param va: address in target function
    :return: dict which maps address -> access type
    """
    mem_operand_types = [eh.analysisHelper.o_mem, eh.analysisHelper.o_phrase, eh.analysisHelper.o_displ]
    va = eh.analysisHelper.getFuncStart(va)
    fend = eh.analysisHelper.getFuncEnd(va)
    mov_types = dict()
    while va < fend:
        if eh.analysisHelper.getMnem(va).lower() == "mov":
            if eh.analysisHelper.getOpndType(va, 0) in mem_operand_types:
                mov_types[va] = UC_MEM_WRITE
            elif eh.analysisHelper.getOpndType(va, 1) in mem_operand_types:
                mov_types[va] = UC_MEM_READ
        va += eh.analysisHelper.getInsnSize(va)
    return mov_types


if __name__ == '__main__':
    # optional argument with sample path to test radare2 support
    if len(sys.argv) == 3:
        eh = flare_emu.EmuHelper(samplePath=sys.argv[1], isRizin=True)
        printfName = "printf"
    elif len(sys.argv) == 2:
        eh = flare_emu.EmuHelper(samplePath=sys.argv[1])
        printfName = "printf"
    else:
        eh = flare_emu.EmuHelper()
        printfName = "_printf"
    print("testing iterate feature for printf function")
    eh.iterate(eh.analysisHelper.getNameAddr(printfName), iterateHook, callHook = ch)

    # currently only test on x86/AMD64
    if eh.arch == UC_ARCH_X86:
        test_memory_access_hook(eh)
