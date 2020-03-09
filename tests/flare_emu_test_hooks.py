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
# NOTE: you may have to rename functions IDA Pro fails to recognize, such as printf
#
# Dependencies:
# https://github.com/fireeye/flare-emu
############################################

from __future__ import print_function
import flare_emu
import sys
import logging

tests = {"from MultiByteToWideChar\r\n":["this is a test".encode("utf-16"), 15], 
         "from WideCharToMultiByte\r\n":["this is a test", 15], 
         "truncated MultiByteToWideChar":["this".encode("utf-16"), 4], 
         "truncated WideCharToMultiByte":["this", 4], 
         "strcpy to HeapAlloc":["this is a test"], 
         "lstrcpy to HeapAlloc":["this is a test"], 
         "HeapReAlloc":["this is a test"], 
         "fixed LocalAlloc\r\n":["this is a test"], 
         "fixed LocalAlloc with padding":["this"], 
         "movable LocalAlloc":["this is a test"], 
         "LocalReAlloc":["this is a test"], 
         "mbstowcs":["this is a test".encode("utf-16"), 14], 
         "mbtowc":["t".encode("utf-16"), 1], 
         "VirtualAllocEx":["this".encode("utf-16")], 
         "malloc\r\n":["this".encode("utf-16")], 
         "malloc with padding":["test".encode("utf-16")], 
         "calloc":["this".encode("utf-16")], 
         "memcpy to offset":["test"], 
         "strlen":["this is a test", 14], 
         "strnlen":["this is a test", 2], 
         "wcslen":["this".encode("utf-16"), 4], 
         "wcsnlen":["this".encode("utf-16"), 2], 
         "strcmp":["this is a test", "this is a test", 0], 
         "stricmp":["THIS IS A TEST", "this is a test", 0], 
         "strncmp":["this is a mess", "this is a test", 0], 
         "strnicmp":["THIS IS A MESS", "this is a test", 0], 
         "wcscmp":["this is a test".encode("utf-16"), "this is a test".encode("utf-16"), 0], 
         "wcsicmp":["THIS IS A TEST".encode("utf-16"), "this is a test".encode("utf-16"), 0], 
         "wcsncmp":["this is a mess".encode("utf-16"), "this is a test".encode("utf-16"), 0], 
         "wcsnicmp":["THIS IS A MESS".encode("utf-16"), "this is a test".encode("utf-16"), 0], 
         "strchr":[97, 8, "this is a test"], 
         "wcschr":[97, 8, "this is a test".encode("utf-16")], 
         "strrchr":[116, 13, "this is a test"], 
         "wcsrchr":[116, 13, "this is a test".encode("utf-16")], 
         "strcat":["The Quick Brown Fox Jumps Over The Lazy Dog"], 
         "strlwr":["the quick brown fox jumps over the lazy dog"], 
         "wcscat":["The Quick Brown Fox Jumps Over The Lazy Dog".encode("utf-16")], 
         "wcslwr":["the quick brown fox jumps over the lazy dog".encode("utf-16")], 
         "strdup":["the quick brown fox jumps over the lazy dog"], 
         "wcsdup":["the quick brown fox jumps over the lazy dog".encode("utf-16")]
        }
 
def iterateHook(eh, address, argv, userData):
    testString = eh.getEmuString(argv[0]).decode("latin1")
    for test in tests:
        if test in testString:
            print("testing '%s'" % testString.replace("\r\n", ""))
            for i in range(len(tests[test])):
                if isinstance(tests[test][i], bytes) or isinstance(tests[test][i], str) :
                    if tests[test][i][:2] == b"\xff\xfe":
                        expected = tests[test][i][2:]
                        actual = eh.getEmuWideString(argv[i+1])
                    else:
                        expected = tests[test][i]
                        actual = eh.getEmuString(argv[i+1]).decode("latin1")
                else:
                    expected = tests[test][i]
                    actual = argv[i+1]
                
                if expected != actual:
                    print("FAILED: %s does not match expected result %s" % (actual,expected))
            return
    print("%s: test not found" % (testString.replace("\r\n", "")))
    
def wcsdupHook(eh, address, argv, funcName, userData):
    print("the new wcsdup hook was called")
    eh.hookCalled = True
    if eh.isValidEmuPtr(argv[0]):
        s = "the quick brown fox jumps over the lazy dog".encode("utf-16")[2:]
        memAddr = eh.allocEmuMem(len(s) + 2)
        eh.uc.mem_write(memAddr, s)
        eh.uc.reg_write(eh.regs["ret"], memAddr)
        return
    
    eh.uc.reg_write(eh.regs["ret"], 0)

if __name__ == '__main__':     
    # optional argument with sample path to test radare2 support
    if len(sys.argv) == 2:
        eh = flare_emu.EmuHelper(samplePath=sys.argv[1])
    else:
        eh = flare_emu.EmuHelper()
        
    eh.analysisHelper.setName(0x41141a, "printf")
    print("testing iterate feature for printf function")
    strcpyEa = eh.analysisHelper.getNameAddr("j_strcpy")
    eh.iterate(eh.analysisHelper.getNameAddr("printf"), iterateHook)
    eh.analysisHelper.setName(strcpyEa, "testname")
    eh.addApiHook("testname", "strcpy")
    eh.addApiHook("wcsdup", wcsdupHook)
    print("testing with renamed and redirected strcpy hook and new hook for wcsdup")
    eh.iterate(eh.analysisHelper.getNameAddr("printf"), iterateHook)
    if "hookCalled" not in dir(eh):
        print("FAILED: addApiHook hook not called")
    
