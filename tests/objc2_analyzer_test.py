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
# objc2_analyzer_test is an IDApython script for testing objc2_analyzer.py
#
# Dependencies:
# https://github.com/fireeye/flare-emu
############################################

from __future__ import print_function
import idc
import idaapi
import idautils
import objc2_analyzer
import logging

comments = ['[(NSString *)_myVar stringByAppendingString_]', 
            '[(SimpleClass2 *)self myVar]', 
            '[[(SimpleClass2 *)self myVar] stringByAppendingString_]', 
            '[SimpleClass2 new]', 
            '[(NSString *)_myVar stringByAppendingString_]', 
            '[(SimpleClass2 *)_sc setMyVar_]', 
            '[(SimpleClass2 *)_sc func1]', 
            '[(SimpleClass *)instance myVar]', 
            '[SimpleClass new]', 
            '[[SimpleClass new] setMyVar_]', 
            '[@"test" stringByAppendingString_]', 
            '[@"test" stringByAppendingString_]', 
            '[[SimpleClass new] myVar]', 
            '[[[SimpleClass new] myVar] stringByAppendingString_]', 
            '[[SimpleClass new] func1]', 
            '[[SimpleClass new] func2]', 
            '[SimpleClass new]', 
            '[SimpleClass func3_]']
          
ARMComments = ['[(NSString *)_myVar stringByAppendingString_]',
               '[(SimpleClass2 *)self myVar]',
               '[(NSString *)_myVar stringByAppendingString_]',
               '[(SimpleClass2 *)_sc setMyVar_]',
               '[(SimpleClass *)instance myVar]',
               '[[(SimpleClass2 *)self myVar] stringByAppendingString_]',
               '[SimpleClass2 new]',
               '[(SimpleClass2 *)_sc func1]',
               '[SimpleClass new]',
               '[[SimpleClass new] setMyVar_]',
               '[@"test" stringByAppendingString_]',
               '[@"test" stringByAppendingString_]',
               '[[SimpleClass new] myVar]',
               '[[[SimpleClass new] myVar] stringByAppendingString_]',
               '[[SimpleClass new] func1]',
               '[[SimpleClass new] func2]',
               '[SimpleClass new]',
               '[SimpleClass func3_]']

imps = ["-[SimpleClass init]",
        "-[SimpleClass2 init]",
        "-[SimpleClass2 myVar]",
        "-[SimpleClass2 func1]",
        "-[SimpleClass2 setMyVar:]",
        "-[SimpleClass func1]",
        "-[SimpleClass func2]",
        "+[SimpleClass func3:]",
        "-[SimpleClass myVar]",
        "-[SimpleClass setMyVar:]"]

selRefs = ["selRef_myVar",
           "selRef_init",
           "selRef_setMyVar:",
           "selRef_func1",
           "selRef_func2",
           "selRef_func3:"]
           
if __name__ == '__main__':   
    fmt = "[%(filename)s:%(lineno)s - %(funcName)20s() ] %(message)s"
    info = idaapi.get_inf_structure()
    if info.procName == "metapc":
        if info.is_64bit():
            arch = "x64"
        elif info.is_32bit():
            print("architecture not supported..")
            exit(1)
    elif info.procName == "ARM":
        if info.is_64bit():
            arch = "ARM64"
        elif info.is_32bit():
            arch = "ARM"
    else:
        print("architecture not supported..")
        exit(1)
        
    # get selref xrefs that will be patched by objc2_analyzer BEFORE processing
    # the instructions will change and we will no longer know which xrefs we
    # need to check for ARM/ARM64 binaries
    selRefsXrefs = {}
    for selRef in selRefs:
        selRefsXrefs[selRef] = []
        for x in idautils.XrefsTo(idc.get_name_ea_simple(selRef)):
            if arch == "ARM":
                if idc.print_insn_mnem(x.frm)[:3] == "MOV":
                    selRefsXrefs[selRef].append(x.frm)
            elif arch == "ARM64":
                # for Link Time Optimized binaries we look for LDR instructions whose src operand
                # begins with "=" to differentiate from non LTO binaries
                # for non LTO binaries, we patch the ADRP/ADRL instructions that reference the selrefs
                if (idc.print_insn_mnem(x.frm) == "ADRP" or
                    idc.print_insn_mnem(x.frm) == "ADRL" or
                        (idc.print_insn_mnem(x.frm)[:3] == "LDR" and 
                         idc.print_operand(x.frm, 1)[0] == "=")):
                    selRefsXrefs[selRef].append(x.frm)
            else:
                selRefsXrefs[selRef].append(x.frm)
        
    # run analyzer
    objc2_analyzer.Objc2Analyzer()
    baseAddr = idc.get_inf_attr(idc.INF_MIN_EA)
    endAddr = idc.get_inf_attr(idc.INF_MAX_EA)
    idc.plan_and_wait(baseAddr, endAddr)
    
    #start tests
    print("objc2_analyzer_test: TESTING COMMENTS")
    
    msgSendXrefs = list(idautils.XrefsTo(idc.get_name_ea_simple("_objc_msgSend")))
    # IDA gets the xrefs in places we are not interested
    # we rely on objc2_analyzer's new xrefs to help our testing
    if arch == "ARM":
        i = 0
        while i < len(msgSendXrefs):
            if idc.print_insn_mnem(msgSendXrefs[i].frm) != "BLX":
                del(msgSendXrefs[i])
                continue
            i += 1
            
    for i, x in enumerate(msgSendXrefs):
        cmt = idc.get_cmt(x.frm, False)
        if arch == "ARM":
            if cmt != ARMComments[i]:
                print("objc2_analyzer_test FAILED: incorrect comment @ %016X" % x.frm)
        else:
            if cmt != comments[i]:
                print("objc2_analyzer_test FAILED: incorrect comment @ %016X" % x.frm)
            
    impAddrs = []
    print("objc2_analyzer_test: TESTING XREFS TO IMPS")
    for imp in imps:
        addr = idc.get_name_ea_simple(imp)
        impAddrs.append(addr)
        if arch == "ARM":
            if len(list(idautils.XrefsTo(addr))) < 1:
                print("objc2_analyzer_test FAILED: xrefs not added to IMP %s" % imp)
        else:
            if len(list(idautils.XrefsTo(addr))) < 2:
                print("objc2_analyzer_test FAILED: xrefs not added to IMP %s" % imp)
    
    print("objc2_analyzer_test: TESTING PATCHED SELREFS")
    for selRef in selRefsXrefs:
        for xref in selRefsXrefs[selRef]:
            if arch == "x64":
                if idc.get_operand_value(xref, 1) not in impAddrs:
                    print("objc2_analyzer_test FAILED: %s not replaced with pointer to IMP @ %016X" 
                          % (selRef, xref))
            elif arch == "ARM":
                if idc.get_operand_value(xref, 0) not in impAddrs and idc.get_operand_value(xref, 0) - 2 not in impAddrs:
                    print("objc2_analyzer_test FAILED: %s not replaced with pointer to IMP @ %016X" 
                          % (selRef, xref))
            elif arch == "ARM64":
                if idc.get_operand_value(xref, 0) not in impAddrs:
                    print("objc2_analyzer_test FAILED: %s not replaced with pointer to IMP @ %016X" 
                          % (selRef, xref))