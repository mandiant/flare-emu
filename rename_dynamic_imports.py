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
# IDApython script that names global variables after their import names when dynamically resolved using GetProcAddress
# Point it to a target function (or somewhere within the function) to begin emulation from
#
# Dependencies:
# https://github.com/fireeye/flare-emu
############################################

import flare_emu
import struct
import idc
import idautils
import logging


def makeName(addr, name):
    names = list(map(lambda x: x[1], list(idautils.Names())))
    i = 0
    myname = name
    while myname in names:
        myname = name + "_%d" % i
        i += 1

    idc.set_name(addr, myname, idc.SN_CHECK)


def instructionHook(uc, address, size, userData):
    try:
        eh = userData["EmuHelper"]
        if (idc.print_insn_mnem(address) == "mov" and
                idc.get_operand_type(address, 0) == 2 and
                idc.get_name(idc.get_operand_value(address, 0))[:6] == "dword_"):
            if "imp" in userData:
                makeName(idc.get_operand_value(address, 0), userData["imp"])
                del(userData["imp"])

    except Exception as err:
        print("Error in instructionHook: %s" % str(err))
        eh.stopEmulation(userData)


def callHook(address, argv, funcName, userData):
    try:
        eh = userData["EmuHelper"]
        # save last import string passed to a call to GetProcAddress
        if funcName == "GetProcAddress":
            arg = eh.getEmuString(argv[1])
            if len(arg) > 2:
                userData["imp"] = arg
            # for code that checks for a return value
            eh.uc.reg_write(eh.regs["ret"], 1)

    except Exception as err:
        print("Error in callHook: %s" % str(err))
        eh.stopEmulation(userData)


if __name__ == '__main__':
    eh = flare_emu.EmuHelper()
    sVa = idc.ida_kernwin.ask_str("0", 0, "Enter the start address (hex)")
    sVa = int(sVa, 16)
    eVa = idc.ida_kernwin.ask_str("0", 0, "Enter the end address (hex), specify 0 to emulate to end of function")
    eVa = int(eVa, 16)
    if (sVa >= idc.get_inf_attr(idc.INF_MIN_EA) and sVa <= idc.get_inf_attr(idc.INF_MAX_EA) and
            (eVa == 0 or (eVa >= idc.get_inf_attr(idc.INF_MIN_EA) and eVa <= idc.get_inf_attr(idc.INF_MAX_EA)))):
        if eVa == 0:
            eVa = None
        mu = eh.emulateRange(sVa, eVa, instructionHook=instructionHook, callHook=callHook)
    else:
        print("Error: supplied addresses not within IDB address range")
