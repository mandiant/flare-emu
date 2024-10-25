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
# flare-emu combines Unicorn and a choice of binary analysis engine to provide emulation support for
# reverse engineers
# Currently supports 32-bit and 64-bit x86, ARM, and ARM64
# Dependencies:
# https://github.com/unicorn-engine/unicorn
############################################

from __future__ import print_function
import unicorn
import unicorn.x86_const
import unicorn.arm_const
import unicorn.arm64_const
from copy import deepcopy
import logging
import struct
import re
import flare_emu_hooks
import types
import sys



PAGESIZE = 0x1000
PAGEALIGNCHECK = 0xfff
X86NOP = b"\x90"
ARMTHUMBNOP = b"\x00\xbf"
ARMNOP = b"\x00\xf0\x20\xe3"
ARM64NOP = b"\x1f\x20\x03\xd5"
MAX_ALLOC_SIZE = 10 * 1024 * 1024
MAXCODEPATHS = 20
MAXNODESEARCH = 100000
try:
    long        # Python 2
except NameError:
    long = int  # Python 3

# parent class to provide binary analysis engine support for EmuHelper class
# subclassed by Radare2AnalysisHelper and IdaProAnalysisHelper
class AnalysisHelper(object):
    def __init__(self):
        self.o_reg = 1
        self.o_mem = 2
        self.o_phrase = 3
        self.o_displ = 4
        self.o_imm = 5
        self.o_far = 6
        self.o_near = 7

    def getFuncStart(self, addr):
        pass

    def getFuncEnd(self, addr):
        pass

    def getFuncName(self, addr):
        pass

    def getMnem(self, addr):
        pass

    # gets address of last instruction in the basic block containing addr
    def getBlockEndInsnAddr(self, addr):
        pass

    def skipJumpTable(self, addr):
        pass

    def getMinimumAddr(self):
        pass

    def getMaximumAddr(self):
        pass

    def getBytes(self, addr, size):
        pass

    def getCString(self, addr):
        pass

    def getOperand(self, addr, opndNum):
        pass

    def getWordValue(self, addr):
        pass

    def getDwordValue(self, addr):
        pass

    def getQWordValue(self, addr):
        pass

    def isThumbMode(self, addr):
        pass

    # for segment/section related functions, IDA Pro calls everything segments
    # while Radare2 maintains the distinction. PE's do not have segments, but sections,
    # while ELFs and Mach-Os have both. We will maintain the distinction when the underlying
    # framework supports it.
    def getSegmentName(self, addr):
        pass

    def getSegmentStart(self, addr):
        pass

    def getSegmentEnd(self, addr):
        pass

    # gets the number of defined bytes in the segment containing addr.
    # used when loading the binary to determine how many bytes to copy
    # to emulator memory from each segment, because IDA Pro may have
    # undefined bytes.
    def getSegmentDefinedSize(self, addr):
        pass

    def getSegmentSize(self, addr):
        pass
        
    def getSegments(self):
        pass
        
    def getSectionName(self, addr):
        pass

    def getSectionStart(self, addr):
        pass

    def getSectionEnd(self, addr):
        pass

    def getSectionSize(self, addr):
        pass

    def getSections(self):
        pass

    # gets disassembled instruction with names and comments as a string
    def getDisasmLine(self, addr):
        pass

    def getName(self, addr):
        pass

    def getNameAddr(self, name):
        pass

    def getOpndType(self, addr, opndNum):
        pass

    def getOpndValue(self, addr, opndNum):
        pass

    def makeInsn(self, addr):
        pass

    def createFunction(self, addr):
        pass

    def getFlowChart(self, addr):
        pass

    def getSpDelta(self, addr):
        pass    

    def getXrefsTo(self, addr):
        pass

    def getBlockByAddr(self, addr, flowchart):
        pass

    def getArch(self):
        pass

    def getBitness(self):
        pass

    def getFileType(self):
        pass

    def getInsnSize(self, addr):
        pass

    def isTerminatingBB(self, addr):
        pass

    def getTerminatingBBs(self, flowchart):
        term_bbs = []
        for bb in flowchart:
            if self.isTerminatingBB(bb):
                term_bbs.append(bb)
        return term_bbs

    def getStartBB(self, addr, flowchart):
        funcStart = self.getFuncStart(addr)
        for bb in flowchart:
            if bb.start_ea == funcStart:
                return bb

    def getBlockIdByVA(self, targetVA, flowchart):
        return self.getBlockByVA(targetVA, flowchart).id

    def getBlockByVA(self, targetVA, flowchart):
        for bb in flowchart:
            if targetVA >= bb.start_ea and targetVA < bb.end_ea:
                return bb
                
    def getBlockById(self, id, flowchart):
        for bb in flowchart:
            if bb.id == id:
                return bb

    def skipJumpTable(self, addr):
        pass

    def normalizeFuncName(self, funcName, extra=False):
        pass

    def setName(self, addr, name, size=0):
        pass

    def setComment(self, addr, comment):
        pass


class EmuHelper():
    def __init__(self, verbose=0, emuHelper=None, samplePath=None, isRizin=False):
        self.verbose = verbose
        self.logger = logging.getLogger(__name__)
        self.stack = 0
        self.stackSize = 0x2000
        self.size_DWORD = 4
        self.size_pointer = 0
        self.callMnems = ["CALL", "BL", "BLX", "BLR",
                          "BLXEQ", "BLEQ", "BLREQ"]
        self.paths = {}
        self.filetype = "UNKNOWN"
        self.uc = None
        self.h_userhook = None
        self.h_memaccesshook = None
        self.h_codehook = None
        self.h_memhook = None
        self.h_inthook = None
        self.enteredBlock = False
        self.hookData = {}

        if isRizin:
            try:
                import flare_emu_rizin
            except Exception as e:
                self.logger.error(f"error importing flare_emu_rizin: {e}")
                return
            # copy RizinAnalysisHelper to skip reanalyzing binary and save time
            if emuHelper is not None:
                self.analysisHelper = emuHelper.analysisHelper
                self.analysisHelper.eh = self
            else:
                self.analysisHelper = flare_emu_rizin.RizinAnalysisHelper(
                    samplePath, self
                )
            self.analysisHelperFramework = "Rizin"
        elif samplePath is not None:
            try:
                import flare_emu_radare
            except Exception as e:
                self.logger.error("error importing flare_emu_radare: %s" % e)
                return
                
            # copy Radare2AnalysisHelper to skip reanalyzing binary and save time
            if emuHelper is not None:
                self.analysisHelper = emuHelper.analysisHelper
                self.analysisHelper.eh = self
            else:
                self.analysisHelper = flare_emu_radare.Radare2AnalysisHelper(samplePath, self)
            self.analysisHelperFramework = "Radare2"
        else:
            try:
                import flare_emu_ida
            except:
                self.logger.error("error importing flare_emu_ida: specify samplePath to use radare2 or run under IDA Pro 7+")
                return
            self.analysisHelper = flare_emu_ida.IdaProAnalysisHelper(self)
            self.analysisHelperFramework = "IDA Pro"
            import idaapi
            
            

        self.initEmuHelper()
        if emuHelper is not None:
            self._cloneEmuMem(emuHelper)
        else:
            self.reloadBinary()

    # startAddr: address to start emulation
    # endAddr: address to end emulation, this instruction is not executed. 
    #     if not provided, emulation stops when starting function is exited 
    #     (function must end with a return instruction)
    # registers: a dict whose keys are register names and values are
    #     register values, all unspecified registers will be initialized to 0
    # stack: a list of values to be setup on the stack before emulation.
    #     if X86 you must account for SP+0 (return address).
    #     for the stack and registers parameters, specifying a string will 
    #     allocate memory, write the string to it, and write a pointer to that 
    #     memory in the specified register/arg
    # instructionHook: instruction hook func that runs AFTER emulateRange's hook
    # hookData: user-defined data to be made available in instruction hook
    #     function, care must be taken to not use key names already used by
    #     flare_emu in userData dictionary
    # skipCalls: emulator will skip over call instructions and adjust the
    #     stack accordingly, defaults to True
    # emulateRange will always skip over calls to empty memory
    # callHook: callback function that will be called whenever the emulator
    #     encounters a "call" instruction. keep in mind your skipCalls value
    #     and that emulateRange will always skip over calls to empty memory
    # memAccessHook: hook function that runs when the emulator encounters a
    #     memory read or write
    # hookApis: set to False if you don't want flare-emu to emulate common 
    #     runtime memory and string functions, defaults to True
    # returns the emulation object in its state after the emulation completes
    # strict: checks branch destinations to ensure the disassembler expects
    #     instructions, otherwise skips branch instruction. if disabled, 
    #     will make code in disassembler as it emulates (DISABLE WITH CAUTION). 
    #     enabled by default
    # count: Value passed to unicorn's uc_emu_start to indicate max number of
    #     instructions to emulate, Defaults to 0 (all code available).
    def emulateRange(self, startAddr, endAddr=None, registers=None, stack=None, instructionHook=None, callHook=None,
                     memAccessHook=None, hookData=None, skipCalls=True, hookApis=True, strict=True, count=0):
        if registers is None:
            registers = {}
        if stack is None:
            stack = []
        userData = {"EmuHelper": self, "funcStart": self.analysisHelper.getFuncStart(startAddr),
                    "funcEnd": self.analysisHelper.getFuncEnd(startAddr), "skipCalls": skipCalls, "strict": strict,
                    "endAddr": endAddr, "callHook": callHook, "hookApis": hookApis, "count": count}
        if hookData:
            userData.update(hookData)
        if userData["funcEnd"] is None:
            userData["funcEnd"] = userData["endAddr"]
        mu = self.uc
        self._prepEmuContext(registers, stack)
        self.resetEmuHooks()
        self.h_codehook = mu.hook_add(
            unicorn.UC_HOOK_CODE, self._emulateRangeCodeHook, userData)
        if instructionHook:
            self.h_userhook = mu.hook_add(unicorn.UC_HOOK_CODE, instructionHook, userData)
        if memAccessHook:
            self.h_memaccesshook = self.uc.hook_add(unicorn.UC_HOOK_MEM_READ | unicorn.UC_HOOK_MEM_WRITE, 
                                                    memAccessHook, userData)
        self.h_memhook = mu.hook_add(unicorn.UC_HOOK_MEM_READ_UNMAPPED | unicorn.UC_HOOK_MEM_WRITE_UNMAPPED |
                                     unicorn.UC_HOOK_MEM_FETCH_UNMAPPED, self._hookMemInvalid, userData)
        self.h_inthook = mu.hook_add(
            unicorn.UC_HOOK_INTR, self._hookInterrupt, userData)
        if self.arch == unicorn.UC_ARCH_ARM:
            userData["changeThumbMode"] = True
        mu.emu_start(startAddr, userData["funcEnd"], count=count)
        self.hookData = userData
        return mu
        
    # call emulateRange using selected instructions in IDA Pro as start/end addresses
    def emulateSelection(self, registers=None, stack=None, instructionHook=None, callHook=None,
                     memAccessHook=None, hookData=None, skipCalls=True, hookApis=True, count=0):
        import idaapi
        try:
            selection = idaapi.read_selection()
        except TypeError:
            selection = idaapi.read_range_selection(None)
        if selection[0]:
            self.emulateRange(selection[1], selection[2], registers, stack, instructionHook, 
                              callHook, memAccessHook, hookData, skipCalls, hookApis, count=count)
        else:
            self.logger.error("emulateSelection is only available for IDA Pro")

    # target: finds first path through function to target using depth first
    #     search for each address in list, if a single address is specified,
    #     does so for each xref to target address
    #     emulates each target's function, forcing path to target, then
    #     executes callback function providing emu object and arguments
    # instructionHook: user-defined instruction hook to run AFTER guidedHook that
    #     forces execution
    # hookData: user-defined data to be made available in instruction hook
    #     function, care must be taken to not use key names already used by
    #     flare_emu in userData dictionary
    # preEmuCallback: a callback that is called BEFORE each emulation run
    # callHook: a callback that is called whenever the emulator encounters a
    #     "call" instruction. hook or no, after a call instruction, the
    #     program counter is advanced to the next instruction and the stack is
    #     automatically cleaned up
    # resetEmuMem: if set to True, unmaps all allocated emulator memory and
    #     reloads the binary from the IDB into emulator memory before each
    #     emulation run. can significantly increase script run time, defaults
    #     to False
    # hookApis: set to False if you don't want flare-emu to emulate common 
    # runtime memory and string functions, defaults to True
    # memAccessHook: hook function that runs when the emulator encounters a
    #     memory read or write
    def iterate(self, target, targetCallback, preEmuCallback=None, callHook=None, instructionHook=None,
                hookData=None, resetEmuMem=False, hookApis=True, memAccessHook=None):
        if target is None:
            return

        targetInfo = {}
        if type(target) in [int, long]:
            self.logger.debug("iterate target function: %s" %
                          self.hexString(target))
            xrefs = self.analysisHelper.getXrefsTo(target)
            for i, x in enumerate(xrefs):
                # get unique functions from xrefs that we need to emulate
                funcStart = self.analysisHelper.getFuncStart(x)
                if funcStart == None:
                    continue
                if self.analysisHelper.getMnem(x).upper() not in ["CALL", "JMP", "BL", "BLX", "B", "BLR"]:
                    continue

                self.logger.debug("getting a path to %s, %d of %d" %
                              (self.hexString(x), i + 1, len(xrefs)))
                flow, paths = self.getPath(x)
                if flow is not None:
                    targetInfo[x] = (flow, paths)
        elif isinstance(target, list):
            for i, t in enumerate(target):
                self.logger.debug("getting a path to %s, %d of %d" %
                              (self.hexString(t), i + 1, len(target)))
                flow, paths = self.getPath(t)
                if flow is not None:
                    targetInfo[t] = (flow, paths)
        if len(targetInfo) <= 0:
            self.logger.debug("no targets to iterate")
            return

        userData = {}
        userData["targetInfo"] = targetInfo
        userData["targetCallback"] = targetCallback
        userData["callHook"] = callHook
        userData["EmuHelper"] = self
        userData["hookApis"] = hookApis
        if hookData:
            userData.update(hookData)
        self.resetEmuHooks()
        self.h_codehook = self.uc.hook_add(
            unicorn.UC_HOOK_CODE, self._guidedHook, userData)
        if instructionHook:
            self.h_userhook = self.uc.hook_add(unicorn.UC_HOOK_CODE, instructionHook, userData)
        if memAccessHook:
            self.h_memaccesshook = self.uc.hook_add(unicorn.UC_HOOK_MEM_READ | unicorn.UC_HOOK_MEM_WRITE, 
                                                    memAccessHook, userData)
        self.h_memhook = self.uc.hook_add(unicorn.UC_HOOK_MEM_READ_UNMAPPED | unicorn.UC_HOOK_MEM_WRITE_UNMAPPED |
                                          unicorn.UC_HOOK_MEM_FETCH_UNMAPPED, self._hookMemInvalid, userData)
        self.h_inthook = self.uc.hook_add(
            unicorn.UC_HOOK_INTR, self._hookInterrupt, userData)
        self.blockIdx = 0
        cnt = 1

        # read targets from dict to go from higher to lower addresses
        # this is done to optimize loop by allowing hook to check for and remove other targets visited en route to
        # current target
        prev_target_info_len = len(userData["targetInfo"])
        while len(userData["targetInfo"]) > 0:
            # Fixes potential edge-case for infinite loop where the target VAs are never reached
            #  and the length never decreases. This modification verifies that the target VAs
            #  are being deleted; otherwise, breaks out of the while loop.
            if cnt > 1 and len(userData["targetInfo"]) == prev_target_info_len:
                break
            prev_target_info_len = len(userData["targetInfo"])

            userData["targetVA"] = targetVA = sorted(
                userData["targetInfo"].keys(), reverse=True)[0]
            flow, paths = userData["targetInfo"][targetVA]
            funcStart = flow[0][0]
            self.pathIdx = 0
            numTargets = len(userData["targetInfo"])
            self.logger.debug("iterate run #%d, %d targets remaining: %s (%d paths)" % (
                cnt, numTargets, self.hexString(targetVA), len(paths)))
            cnt2 = 1
            numPaths = len(paths)
            for path in paths:
                self.logger.debug("emulating path #%d of %d from %s to %s via basic blocks: %s" % (
                    cnt2, numPaths, self.hexString(funcStart), self.hexString(targetVA), repr(path)))
                for reg in self.regs:
                    self.uc.reg_write(self.regs[reg], 0)
                if resetEmuMem:
                    self.reloadBinary()
                self.uc.reg_write(self.regs["sp"], self.stack)
                self.enteredBlock = False
                userData["visitedTargets"] = []
                if preEmuCallback:
                    preEmuCallback(self, userData, funcStart)
                if self.arch == unicorn.UC_ARCH_ARM:
                    userData["changeThumbMode"] = True

                self.uc.emu_start(funcStart, self.analysisHelper.getFuncEnd(funcStart))
                self.pathIdx += 1
                self.blockIdx = 0
                cnt2 += 1
                # remove visited targets during this run from our dict
                for addr in userData["visitedTargets"]:
                    del(userData["targetInfo"][addr])

            cnt += 1

        self.hookData = userData

    # target: iterates paths through a function
    # targetCallback: a callback that is called when target (function end)
    #     is hit, providing arguments and userData
    # preEmuCallback: a callback that is called BEFORE each emulation run
    # callHook: a callback that is called whenever the emulator encounters a
    #     "call" instruction. hook or no, after a call instruction, the
    #     program counter is advanced to the next instruction and the stack is
    #     automatically cleaned up
    # instructionHook: user-defined instruction hook to run AFTER guidedHook that
    #     forces execution
    # hookData: user-defined data to be made available in instruction hook
    #     function, care must be taken to not use key names already used by
    #     flare_emu in userData dictionary
    # resetEmuMem: if set to True, unmaps all allocated emulator memory and
    #     reloads the binary from the IDB into emulator memory before each
    #     emulation run. can significantly increase script run time, defaults
    #     to False
    # hookApis: set to False if you don't want flare-emu to emulate common
    #     runtime memory and string functions, defaults to True
    # memAccessHook: hook function that runs when the emulator encounters a
    #     memory read or write
    # maxPaths: maximum number of paths to discover and emulate for a function
    # maxNodes: maximum number of nodes to go through before giving up
    def iterateAllPaths(self, target, targetCallback, preEmuCallback=None, callHook=None, instructionHook=None,
                        hookData=None, resetEmuMem=False, hookApis=True, memAccessHook=None, maxPaths=MAXCODEPATHS,
                        maxNodes=MAXNODESEARCH):
        flowchart = self.analysisHelper.getFlowChart(target)
        # targets are all function ends
        targets = [self.analysisHelper.getBlockEndInsnAddr(bb.start_ea, flowchart) for bb 
                   in self.analysisHelper.getTerminatingBBs(flowchart)]

        targetInfo = {}
        for i, t in enumerate(targets):
            self.logger.debug("getting paths to %s, %d of %d targets" %
                          (self.hexString(t), i + 1, len(targets)))
            flow, paths = self.getPathsToTarget(t, maxPaths, maxNodes)
            if flow and paths:
                targetInfo[t] = (flow, paths)
        if len(targetInfo) <= 0:
            self.logger.debug("iterateAllPaths: no targets to iterate for %s" % self.hexString(target))
            return

        userData = {}
        userData["targetInfo"] = targetInfo
        userData["targetCallback"] = targetCallback
        userData["callHook"] = callHook
        userData["EmuHelper"] = self
        userData["hookApis"] = hookApis
        if hookData:
            userData.update(hookData)
        self.internalRun = False
        self.resetEmuHooks()
        self.h_codehook = self.uc.hook_add(
            unicorn.UC_HOOK_CODE, self._guidedHook, userData)
        if instructionHook:
            self.h_userhook = self.uc.hook_add(unicorn.UC_HOOK_CODE, instructionHook, userData)
        if memAccessHook:
            self.h_memaccesshook = self.uc.hook_add(unicorn.UC_HOOK_MEM_READ | unicorn.UC_HOOK_MEM_WRITE, 
                                                    memAccessHook, userData)
        self.h_memhook = self.uc.hook_add(unicorn.UC_HOOK_MEM_READ_UNMAPPED | unicorn.UC_HOOK_MEM_WRITE_UNMAPPED |
                                          unicorn.UC_HOOK_MEM_FETCH_UNMAPPED, self._hookMemInvalid, userData)
        self.h_inthook = self.uc.hook_add(
            unicorn.UC_HOOK_INTR, self._hookInterrupt, userData)
        self.blockIdx = 0
        cnt = 1

        for targetVA in sorted(userData["targetInfo"].keys(), reverse=True):
            userData["targetVA"] = targetVA
            flow, paths = userData["targetInfo"][targetVA]
            funcStart = flow[0][0]
            self.pathIdx = 0
            numTargets = len(userData["targetInfo"])
            self.logger.debug("run #%d, %d targets remaining: %s (%d paths)" % (
            cnt, numTargets, self.hexString(targetVA), len(paths)))
            cnt2 = 1
            numPaths = len(paths)
            for path in paths:
                self.logger.debug("emulating path #%d of %d from %s to %s via basic blocks: %s" % (
                    cnt2, numPaths, self.hexString(funcStart), self.hexString(targetVA), repr(path)))
                for reg in self.regs:
                    self.uc.reg_write(self.regs[reg], 0)
                if resetEmuMem:
                    self.reloadBinary()
                self.uc.reg_write(self.regs["sp"], self.stack)
                self.enteredBlock = False
                userData["visitedTargets"] = []
                if preEmuCallback:
                    preEmuCallback(self, userData, funcStart)
                if self.arch == unicorn.UC_ARCH_ARM:
                    userData["changeThumbMode"] = True

                self.uc.emu_start(funcStart, self.analysisHelper.getFuncEnd(funcStart))
                self.pathIdx += 1
                self.blockIdx = 0
                cnt2 += 1
            cnt += 1

        self.hookData = userData

    # simply emulates to the end of whatever bytes are provided
    # these bytes are not loaded into IDB, only emulator memory
    # analysisHelper APIs are not available for use in hooks here
    def emulateBytes(self, bytes, registers=None, stack=None, baseAddr=0x400000, instructionHook=None,
                     memAccessHook=None, hookData=None):
        if registers is None:
            registers = {}
        if stack is None:
            stack = []
        userData = {}
        if hookData:
            userData.update(hookData)
        baseAddr = self.loadBytes(bytes, baseAddr)
        endAddr = baseAddr + len(bytes)
        userData["endAddr"] = endAddr
        mu = self.uc
        self._prepEmuContext(registers, stack)
        self.resetEmuHooks()
        self.h_codehook = mu.hook_add(
            unicorn.UC_HOOK_CODE, self._emulateBytesCodeHook, userData)
        if instructionHook:
            self.h_userhook = mu.hook_add(unicorn.UC_HOOK_CODE, instructionHook, userData)
        if memAccessHook:
            self.h_memaccesshook = self.uc.hook_add(unicorn.UC_HOOK_MEM_READ | unicorn.UC_HOOK_MEM_WRITE, 
                                                    memAccessHook, userData)
        self.h_memhook = mu.hook_add(unicorn.UC_HOOK_MEM_READ_UNMAPPED | unicorn.UC_HOOK_MEM_WRITE_UNMAPPED |
                                     unicorn.UC_HOOK_MEM_FETCH_UNMAPPED, self._hookMemInvalid, userData)
        self.h_inthook = mu.hook_add(
            unicorn.UC_HOOK_INTR, self._hookInterrupt, userData)
        mu.emu_start(baseAddr, endAddr)
        self.hookData = userData
        return mu
        
    # emulates from startAddr continually
    # must specify conditions under which emulation is stopped such as the "count" param
    # or making a call to eh.stopEmulation from one of your hooks
    # startAddr: address to start emulation
    # registers: a dict whose keys are register names and values are
    #     register values, all unspecified registers will be initialized to 0
    # stack: a list of values to be setup on the stack before emulation.
    #     if X86 you must account for SP+0 (return address).
    #     for the stack and registers parameters, specifying a string will 
    #     allocate memory, write the string to it, and write a pointer to that 
    #     memory in the specified register/arg
    # instructionHook: instruction hook func that runs AFTER emulateFrom's hook
    # hookData: user-defined data to be made available in instruction hook
    #     function, care must be taken to not use key names already used by
    #     flare_emu in userData dictionary
    # skipCalls: emulator will skip over call instructions and adjust the
    #     stack accordingly, defaults to True
    # emulateFrom will always skip over calls to empty memory
    # callHook: callback function that will be called whenever the emulator
    #     encounters a "call" instruction. keep in mind your skipCalls value
    #     and that emulateFrom will always skip over calls to empty memory
    # memAccessHook: hook function that runs when the emulator encounters a
    #     memory read or write
    # hookApis: set to False if you don't want flare-emu to emulate common 
    #     runtime memory and string functions, defaults to True
    # returns the emulation object in its state after the emulation completes
    # strict: checks branch destinations to ensure the disassembler expects
    #     instructions, otherwise skips branch instruction. if disabled, 
    #     will make code in disassembler as it emulates (DISABLE WITH CAUTION). 
    #     enabled by default
    # count: Value passed to unicorn's uc_emu_start to indicate max number of
    #     instructions to emulate, Defaults to 0 (all code available).
    def emulateFrom(self, startAddr, registers=None, stack=None, instructionHook=None, callHook=None,
                     memAccessHook=None, hookData=None, skipCalls=True, hookApis=True, strict=True, count=0):
        if registers is None:
            registers = {}
        if stack is None:
            stack = []
        userData = {"EmuHelper": self, "skipCalls": skipCalls, "callHook": callHook, 
                    "hookApis": hookApis, "strict": strict, "count": count}
        if hookData:
            userData.update(hookData)
        mu = self.uc
        self._prepEmuContext(registers, stack)
        self.resetEmuHooks()
        self.h_codehook = mu.hook_add(
            unicorn.UC_HOOK_CODE, self._emulateRangeCodeHook, userData)
        if instructionHook:
            self.h_userhook = mu.hook_add(unicorn.UC_HOOK_CODE, instructionHook, userData)
        if memAccessHook:
            self.h_memaccesshook = self.uc.hook_add(unicorn.UC_HOOK_MEM_READ | unicorn.UC_HOOK_MEM_WRITE, 
                                                    memAccessHook, userData)
        self.h_memhook = mu.hook_add(unicorn.UC_HOOK_MEM_READ_UNMAPPED | unicorn.UC_HOOK_MEM_WRITE_UNMAPPED |
                                     unicorn.UC_HOOK_MEM_FETCH_UNMAPPED, self._hookMemInvalid, userData)
        self.h_inthook = mu.hook_add(
            unicorn.UC_HOOK_INTR, self._hookInterrupt, userData)
        if self.arch == unicorn.UC_ARCH_ARM:
            userData["changeThumbMode"] = True
        mu.emu_start(startAddr, self.analysisHelper.getMaximumAddr(), count=count)
        self.hookData = userData
        return mu

    def writeEmuMem(self, addr, data):
        if isinstance(data, bytearray):
            data = bytes(data)

        if not isinstance(data, bytes):
            self.logger.error("wrong type for writeEmuMem data, expects bytes or bytearray: %s" % type(data))
            return

        self.uc.mem_write(addr, data)
        
    def hexString(self, va):
        if va > 0xffffffff:
            return "%016X" % va
        else:
            return "%08X" % va

    def pageAlignUp(self, v):
        if v & PAGEALIGNCHECK != 0:
            v += PAGESIZE - (v % PAGESIZE)
        return v

    # determines if the instruction at addr is for returning from a function call
    def isRetInstruction(self, addr):
        if self.analysisHelper.getMnem(addr)[:3].lower() == "ret":
            return True

        if (self.analysisHelper.getMnem(addr).lower() in ["bx", "b"] and 
            self.analysisHelper.getOperand(addr, 0).lower() == "lr"):
            return True

        if (self.analysisHelper.getMnem(addr).lower() == "pop" and 
            "pc" in self.analysisHelper.getDisasmLine(addr).lower()):
            return True

        return False

    # call from an emulation hook to skip the current instruction, moving pc to next instruction
    # useAnalysisHelper option added to handle cases where IDA folds multiple instructions (Radare2 doesn't do this)
    # do not call multiple times in a row, depends on userData being updated by hook
    def skipInstruction(self, userData, useAnalysisHelper=False):
        if self.arch == unicorn.UC_ARCH_ARM:
            userData["changeThumbMode"] = True
        if useAnalysisHelper:
            self.uc.reg_write(self.regs["pc"], 
                              userData["currAddr"] + self.analysisHelper.getInsnSize(userData["currAddr"]))
        else:
            self.uc.reg_write(
                self.regs["pc"], userData["currAddr"] + userData["currAddrSize"])
        # get SP delta value for next instruction to adjust stack accordingly since we are skipping
        # this instruction
        self.uc.reg_write(self.regs["sp"], self.getRegVal(
            "sp") + self.analysisHelper.getSpDelta(userData["currAddr"] + 
            self.analysisHelper.getInsnSize(userData["currAddr"])))
            
    # call from an emulation hook to change program counter
    def changeProgramCounter(self, userData, newPC):
        if self.arch == unicorn.UC_ARCH_ARM:
            userData["changeThumbMode"] = True
        self.uc.reg_write(self.regs["pc"], newPC)

    # retrieves the value of a register, handling subregister addressing
    def getRegVal(self, regName):
        regVal = self.uc.reg_read(self.regs[regName])
        # handle various subregister addressing
        if self.arch == unicorn.UC_ARCH_X86:
            if regName[:-1] in ["l", "b"]:
                regVal = regVal & 0xFF
            elif regName[:-1] == "h":
                regVal = (regVal & 0xFF00) >> 8
            elif len(regName) == 2 and regName[:-1] == "x":
                regVal = regVal & 0xFFFF
            elif regName[0] == "e":
                regVal = regVal & 0xFFFFFFFF
            elif regName[:-1] == "d":
                regVal = regVal & 0xFFFFFFFF
            elif regName[:-1] == "w":
                regVal = regVal & 0xFFFF
        elif self.arch == unicorn.UC_ARCH_ARM64:
            if regName[0] == "W":
                regVal = regVal & 0xFFFFFFFF
        return regVal

    def stopEmulation(self, userData):
        self.enteredBlock = False
        if "visitedTargets" in userData and userData["targetVA"] not in userData["visitedTargets"]:
            userData["visitedTargets"].append(
                userData["targetVA"])
        self.uc.emu_stop()

    def resetEmuHooks(self):
        if self.uc is None:
            self.logger.debug(
                "resetEmuHooks: no hooks to reset, emulator has not been initialized yet")
            return
        if self.h_userhook:
            self.uc.hook_del(self.h_userhook)
            self.h_userhook = None
        if self.h_memaccesshook:
            self.uc.hook_del(self.h_memaccesshook)
            self.h_memaccesshook = None
        if self.h_codehook:
            self.uc.hook_del(self.h_codehook)
            self.h_codehook = None
        if self.h_memhook:
            self.uc.hook_del(self.h_memhook)
            self.h_memhook = None
        if self.h_inthook:
            self.uc.hook_del(self.h_inthook)
            self.h_inthook = None

    def getHookData(self):
        return self.hookData

    # for debugging purposes
    def getEmuState(self):
        if self.arch == unicorn.UC_ARCH_X86:
            if self.uc._mode == unicorn.UC_MODE_64:
                out = "RAX: %016X\tRBX: %016X\n" % (self.uc.reg_read(
                    unicorn.x86_const.UC_X86_REG_RAX), self.uc.reg_read(unicorn.x86_const.UC_X86_REG_RBX))
                out += "RCX: %016X\tRDX: %016X\n" % (self.uc.reg_read(
                    unicorn.x86_const.UC_X86_REG_RCX), self.uc.reg_read(unicorn.x86_const.UC_X86_REG_RDX))
                out += "RDI: %016X\tRSI: %016X\n" % (self.uc.reg_read(
                    unicorn.x86_const.UC_X86_REG_RDI), self.uc.reg_read(unicorn.x86_const.UC_X86_REG_RSI))
                out += "R8: %016X\tR9: %016X\n" % (self.uc.reg_read(
                    unicorn.x86_const.UC_X86_REG_R8), self.uc.reg_read(unicorn.x86_const.UC_X86_REG_R9))
                out += "RBP: %016X\tRSP: %016X\n" % (self.uc.reg_read(
                    unicorn.x86_const.UC_X86_REG_RBP), self.uc.reg_read(unicorn.x86_const.UC_X86_REG_RSP))
                out += "RIP: %016X\n" % (self.uc.reg_read(unicorn.x86_const.UC_X86_REG_RIP))
            elif self.uc._mode == unicorn.UC_MODE_32:
                out = "EAX: %016X\tEBX: %016X\n" % (self.uc.reg_read(
                    unicorn.x86_const.UC_X86_REG_EAX), self.uc.reg_read(unicorn.x86_const.UC_X86_REG_EBX))
                out += "ECX: %016X\tEDX: %016X\n" % (self.uc.reg_read(
                    unicorn.x86_const.UC_X86_REG_ECX), self.uc.reg_read(unicorn.x86_const.UC_X86_REG_EDX))
                out += "EDI: %016X\tESI: %016X\n" % (self.uc.reg_read(
                    unicorn.x86_const.UC_X86_REG_EDI), self.uc.reg_read(unicorn.x86_const.UC_X86_REG_ESI))
                out += "EBP: %016X\tESP: %016X\n" % (self.uc.reg_read(
                    unicorn.x86_const.UC_X86_REG_EBP), self.uc.reg_read(unicorn.x86_const.UC_X86_REG_ESP))
                out += "EIP: %016X\n" % (self.uc.reg_read(unicorn.x86_const.UC_X86_REG_EIP))
        elif self.arch == unicorn.UC_ARCH_ARM64:
            out = "X0: %016X\tX1: %016X\n" % (self.uc.reg_read(
                unicorn.arm64_const.UC_ARM64_REG_X0), self.uc.reg_read(unicorn.arm64_const.UC_ARM64_REG_X1))
            out += "X2: %016X\tX3: %016X\n" % (self.uc.reg_read(
                unicorn.arm64_const.UC_ARM64_REG_X2), self.uc.reg_read(unicorn.arm64_const.UC_ARM64_REG_X3))
            out += "X4: %016X\tX5: %016X\n" % (self.uc.reg_read(
                unicorn.arm64_const.UC_ARM64_REG_X4), self.uc.reg_read(unicorn.arm64_const.UC_ARM64_REG_X5))
            out += "X6: %016X\tX7: %016X\n" % (self.uc.reg_read(
                unicorn.arm64_const.UC_ARM64_REG_X6), self.uc.reg_read(unicorn.arm64_const.UC_ARM64_REG_X7))
            out += "X8: %016X\tX9: %016X\n" % (self.uc.reg_read(
                unicorn.arm64_const.UC_ARM64_REG_X8), self.uc.reg_read(unicorn.arm64_const.UC_ARM64_REG_X9))
            out += "X10: %016X\tX11: %016X\n" % (self.uc.reg_read(
                unicorn.arm64_const.UC_ARM64_REG_X10), self.uc.reg_read(unicorn.arm64_const.UC_ARM64_REG_X11))
            out += "X12: %016X\tX13: %016X\n" % (self.uc.reg_read(
                unicorn.arm64_const.UC_ARM64_REG_X12), self.uc.reg_read(unicorn.arm64_const.UC_ARM64_REG_X13))
            out += "X14: %016X\tX15: %016X\n" % (self.uc.reg_read(
                unicorn.arm64_const.UC_ARM64_REG_X14), self.uc.reg_read(unicorn.arm64_const.UC_ARM64_REG_X15))
            out += "X16: %016X\tX17: %016X\n" % (self.uc.reg_read(
                unicorn.arm64_const.UC_ARM64_REG_X16), self.uc.reg_read(unicorn.arm64_const.UC_ARM64_REG_X17))
            out += "X18: %016X\tX19: %016X\n" % (self.uc.reg_read(
                unicorn.arm64_const.UC_ARM64_REG_X18), self.uc.reg_read(unicorn.arm64_const.UC_ARM64_REG_X19))
            out += "X20: %016X\tX21: %016X\n" % (self.uc.reg_read(
                unicorn.arm64_const.UC_ARM64_REG_X20), self.uc.reg_read(unicorn.arm64_const.UC_ARM64_REG_X21))
            out += "X22: %016X\tX23: %016X\n" % (self.uc.reg_read(
                unicorn.arm64_const.UC_ARM64_REG_X22), self.uc.reg_read(unicorn.arm64_const.UC_ARM64_REG_X23))
            out += "X24: %016X\tX25: %016X\n" % (self.uc.reg_read(
                unicorn.arm64_const.UC_ARM64_REG_X24), self.uc.reg_read(unicorn.arm64_const.UC_ARM64_REG_X25))
            out += "X26: %016X\tX27: %016X\n" % (self.uc.reg_read(
                unicorn.arm64_const.UC_ARM64_REG_X26), self.uc.reg_read(unicorn.arm64_const.UC_ARM64_REG_X27))
            out += "X28: %016X\tX29: %016X\n" % (self.uc.reg_read(
                unicorn.arm64_const.UC_ARM64_REG_X28), self.uc.reg_read(unicorn.arm64_const.UC_ARM64_REG_X29))
            out += "X30: %016X\n" % (self.uc.reg_read(unicorn.arm64_const.UC_ARM64_REG_X30))
            out += "PC: %016X\n" % (self.uc.reg_read(unicorn.arm64_const.UC_ARM64_REG_PC))
            out += "SP: %016X\n" % (self.uc.reg_read(unicorn.arm64_const.UC_ARM64_REG_SP))
        elif self.arch == unicorn.UC_ARCH_ARM:
            out = "R0: %08X\tR1: %08X\n" % (self.uc.reg_read(
                unicorn.arm_const.UC_ARM_REG_R0), self.uc.reg_read(unicorn.arm_const.UC_ARM_REG_R1))
            out += "R2: %08X\tR3: %08X\n" % (self.uc.reg_read(
                unicorn.arm_const.UC_ARM_REG_R2), self.uc.reg_read(unicorn.arm_const.UC_ARM_REG_R3))
            out += "R4: %08X\tR5: %08X\n" % (self.uc.reg_read(
                unicorn.arm_const.UC_ARM_REG_R4), self.uc.reg_read(unicorn.arm_const.UC_ARM_REG_R5))
            out += "R6: %08X\tR7: %08X\n" % (self.uc.reg_read(
                unicorn.arm_const.UC_ARM_REG_R6), self.uc.reg_read(unicorn.arm_const.UC_ARM_REG_R7))
            out += "R8: %08X\tR9: %08X\n" % (self.uc.reg_read(
                unicorn.arm_const.UC_ARM_REG_R8), self.uc.reg_read(unicorn.arm_const.UC_ARM_REG_R9))
            out += "R10: %08X\tR11: %08X\n" % (self.uc.reg_read(
                unicorn.arm_const.UC_ARM_REG_R10), self.uc.reg_read(unicorn.arm_const.UC_ARM_REG_R11))
            out += "R12: %08X\tR13: %08X\n" % (self.uc.reg_read(
                unicorn.arm_const.UC_ARM_REG_R12), self.uc.reg_read(unicorn.arm_const.UC_ARM_REG_R13))
            out += "R14: %08X\tR15: %08X\n" % (self.uc.reg_read(
                unicorn.arm_const.UC_ARM_REG_R14), self.uc.reg_read(unicorn.arm_const.UC_ARM_REG_R15))
            out += "PC: %08X\n" % self.uc.reg_read(unicorn.arm_const.UC_ARM_REG_R15)
            out += "SP: %08X\n" % self.uc.reg_read(unicorn.arm_const.UC_ARM_REG_R13)
        else:
            return ""
        return out

    # returns null-terminated string of bytes from the emulator's memory, starting at addr, do not necessarily need
    # to be printable characters
    def getEmuString(self, addr):
        # return a bytearray object , if you want to get a str object ,you must decode it by  latin1
        out = bytearray()
        while self.uc.mem_read(addr, 1) != b"\x00":
            out += self.uc.mem_read(addr, 1)
            addr += 1
        return out
    
    def getEmuWideString(self, addr):
        # return a bytearray object , if you want to get a str object ,you must decode it by  utf-16le
        out = bytearray()
        while self.uc.mem_read(addr, 2) != b"\x00\x00":
            out += self.uc.mem_read(addr, 2)
            addr += 2
        return out

    # returns a <size> bytearray of bytes read from <addr>
    def getEmuBytes(self, addr, size):
        return self.uc.mem_read(addr, size)

    # reads pointer value in emulator's memory
    def getEmuPtr(self, va):
        return struct.unpack(self.pack_fmt, self.uc.mem_read(va, self.size_pointer))[0]
        
    # writes a pointer value in emulator's memory
    def writeEmuPtr(self, va, value):
        self.writeEmuMem(va, struct.pack(self.pack_fmt, value))
        
    # gets the signed integer value of the unsigned integer value given the bitness of the architecture
    def getSignedValue(self, value):
        return struct.unpack(self.pack_fmt_signed, struct.pack(self.pack_fmt, value))[0]

    def pageAlign(self, addr):
        return addr & 0xfffffffffffff000

    
    # get first path to target found during exploration
    def getPath(self, targetVA):
        flowchart = self.analysisHelper.getFlowChart(targetVA)
        target_bb = self.analysisHelper.getBlockByVA(targetVA, flowchart)
        start_bb = self.analysisHelper.getStartBB(targetVA, flowchart)
        if target_bb.id != 0:
            if self.verbose > 0:
                self.logger.debug("exploring function with %d blocks" % len(flowchart))
            graph = self._explore(start_bb, target_bb)
            if graph is None:
                self.logger.debug(
                    "graph for target %s could not be traversed, skipping" % self.hexString(targetVA))
                return None, None

            if self.verbose > 0:
                self.logger.debug("graph for target:\n%s" % repr(graph))
                
            path = [0]
            if not self._findPathFromGraph(path, graph, 0, target_bb.id):
                self.logger.debug(
                    "path for target %s could not be discovered, skipping" % self.hexString(targetVA))
                return None, None
        else:
            path = [0]

        if self.verbose > 0:
            self.logger.debug("code path to target: %s" % repr(path))

        # create my own idaapi.FlowChart-like object to optimize calculating block end addrs
        flow = {}
        for bb in flowchart:
            flow[bb.id] = (bb.start_ea, self.analysisHelper.getBlockEndInsnAddr(bb.start_ea, flowchart))
        return flow, [path]
        
    # get up to maxPaths path to target
    # for some complex functions, may give up before finding a path
    def getPathsToTarget(self, targetVA, maxPaths=MAXCODEPATHS, maxNodes=MAXNODESEARCH):
        flowchart = self.analysisHelper.getFlowChart(targetVA)
        target_bb = self.analysisHelper.getBlockByVA(targetVA, flowchart)
        start_bb = self.analysisHelper.getStartBB(targetVA, flowchart)
        if target_bb.id != 0:
            if self.verbose > 0:
                self.logger.debug("exploring function with %d blocks" % len(flowchart))
            graph = self._explore(start_bb)
            if graph is None:
                self.logger.debug(
                    "graph for target %s could not be traversed, skipping" % self.hexString(targetVA))
                return None, None

            if self.verbose > 0:
                self.logger.debug("graph for target:\n%s" % repr(graph))
             
            path = [0]
            paths = []
            targets = [target_bb.id]
            self._findPathsFromGraph(paths, path, graph, 0, targets, maxPaths, 0 , maxNodes)
            if len(paths) == 0:
                self.logger.debug(
                    "path for target %s could not be discovered, skipping" % self.hexString(targetVA))
                return None, None
        else:
            paths = [[0]]

        if self.verbose > 0:
            self.logger.debug("code paths to target: %s" % repr(paths))

        # create my own idaapi.FlowChart object so it can be pickled for debugging purposes
        flow = {}
        for bb in flowchart:
            flow[bb.id] = (bb.start_ea, self.analysisHelper.getBlockEndInsnAddr(bb.start_ea, flowchart))
        return flow, paths

    # get up to maxPaths paths from function start to any terminating basic block
    # for some complex functions, may give up before finding a path
    def getPaths(self, fva, maxPaths=MAXCODEPATHS, maxNodes=MAXNODESEARCH):
        flowchart = self.analysisHelper.getFlowChart(fva)
        term_bbs_ids = [bb.id for bb in self.analysisHelper.getTerminatingBBs(flowchart)]
        start_bb = self.analysisHelper.getStartBB(fva, flowchart)
        if term_bbs_ids != [0]:
            if self.verbose > 0:
                self.logger.debug("exploring function with %d blocks" % len(flowchart))
            graph = self._explore(start_bb)
            if graph is None:
                self.logger.debug(
                    "graph for target %s could not be traversed, skipping" % self.hexString(fva))
                return None, None

            if self.verbose > 0:
                self.logger.debug("graph for target:\n%s" % repr(graph))

            path = [0]
            paths = []
            self._findPathsFromGraph(paths, path, graph, 0, term_bbs_ids, maxPaths, 0, maxNodes)
            if len(paths) == 0:
                self.logger.debug(
                    "paths for target %s could not be discovered, skipping" % self.hexString(fva))
                return None, None
        else:
            paths = [[0]]

        if self.verbose > 0:
            self.logger.debug("code paths to target: %s" % repr(paths))

        # create my own idaapi.FlowChart object so it can be pickled for debugging purposes
        flow = {}
        for bb in flowchart:
            flow[bb.id] = (bb.start_ea, self.analysisHelper.getBlockEndInsnAddr(bb.start_ea, flowchart))
        return flow, paths

    # sets up arch/mode specific variables, initializes emulator
    def initEmuHelper(self):
        arch = self.analysisHelper.getArch()
        bitness = self.analysisHelper.getBitness()
        self.filetype = self.analysisHelper.getFileType()
        if arch == "X86":
            self.arch = unicorn.UC_ARCH_X86
            if bitness == 64:
                self.mode = unicorn.UC_MODE_64
                self.derefPtr = self.analysisHelper.getQWordValue
                mode = "64-bit"
                self.size_pointer = 8
                self.pack_fmt = "<Q"
                self.pack_fmt_signed = "<Q"
                self.pageMask = 0xfffffffffffff000
                self.regs = {"ax": unicorn.x86_const.UC_X86_REG_RAX, "bx": unicorn.x86_const.UC_X86_REG_RBX,
                             "cx": unicorn.x86_const.UC_X86_REG_RCX, "dx": unicorn.x86_const.UC_X86_REG_RDX,
                             "di": unicorn.x86_const.UC_X86_REG_RDI, "si": unicorn.x86_const.UC_X86_REG_RSI,
                             "bp": unicorn.x86_const.UC_X86_REG_RBP, "sp": unicorn.x86_const.UC_X86_REG_RSP,
                             "eax": unicorn.x86_const.UC_X86_REG_RAX, "ebx": unicorn.x86_const.UC_X86_REG_RBX,
                             "ecx": unicorn.x86_const.UC_X86_REG_RCX, "edx": unicorn.x86_const.UC_X86_REG_RDX,
                             "edi": unicorn.x86_const.UC_X86_REG_RDI, "esi": unicorn.x86_const.UC_X86_REG_RSI,
                             "ebp": unicorn.x86_const.UC_X86_REG_RBP, "esp": unicorn.x86_const.UC_X86_REG_RSP,
                             "ip": unicorn.x86_const.UC_X86_REG_RIP, "pc": unicorn.x86_const.UC_X86_REG_RIP,
                             "rax": unicorn.x86_const.UC_X86_REG_RAX, "rbx": unicorn.x86_const.UC_X86_REG_RBX,
                             "rcx": unicorn.x86_const.UC_X86_REG_RCX, "rdx": unicorn.x86_const.UC_X86_REG_RDX,
                             "rdi": unicorn.x86_const.UC_X86_REG_RDI, "rsi": unicorn.x86_const.UC_X86_REG_RSI,
                             "rbp": unicorn.x86_const.UC_X86_REG_RBP, "rsp": unicorn.x86_const.UC_X86_REG_RSP,
                             "r8": unicorn.x86_const.UC_X86_REG_R8, "r9": unicorn.x86_const.UC_X86_REG_R9,
                             "r10": unicorn.x86_const.UC_X86_REG_R10, "r11": unicorn.x86_const.UC_X86_REG_R11,
                             "r12": unicorn.x86_const.UC_X86_REG_R12, "r13": unicorn.x86_const.UC_X86_REG_R13,
                             "r14": unicorn.x86_const.UC_X86_REG_R14, "r15": unicorn.x86_const.UC_X86_REG_R15,
                             "r8d": unicorn.x86_const.UC_X86_REG_R8, "r9d": unicorn.x86_const.UC_X86_REG_R9,
                             "r10d": unicorn.x86_const.UC_X86_REG_R10, "r11d": unicorn.x86_const.UC_X86_REG_R11,
                             "r12d": unicorn.x86_const.UC_X86_REG_R12, "r13d": unicorn.x86_const.UC_X86_REG_R13,
                             "r14d": unicorn.x86_const.UC_X86_REG_R14, "r15d": unicorn.x86_const.UC_X86_REG_R15,
                             "r8w": unicorn.x86_const.UC_X86_REG_R8, "r9w": unicorn.x86_const.UC_X86_REG_R9,
                             "r10w": unicorn.x86_const.UC_X86_REG_R10, "r11w": unicorn.x86_const.UC_X86_REG_R11,
                             "r12w": unicorn.x86_const.UC_X86_REG_R12, "r13w": unicorn.x86_const.UC_X86_REG_R13,
                             "r14w": unicorn.x86_const.UC_X86_REG_R14, "r15w": unicorn.x86_const.UC_X86_REG_R15,
                             "r8b": unicorn.x86_const.UC_X86_REG_R8, "r9b": unicorn.x86_const.UC_X86_REG_R9,
                             "r10b": unicorn.x86_const.UC_X86_REG_R10, "r11b": unicorn.x86_const.UC_X86_REG_R11,
                             "r12b": unicorn.x86_const.UC_X86_REG_R12, "r13b": unicorn.x86_const.UC_X86_REG_R13,
                             "r14b": unicorn.x86_const.UC_X86_REG_R14, "r15b": unicorn.x86_const.UC_X86_REG_R15,
                             "ret": unicorn.x86_const.UC_X86_REG_RAX, "rip": unicorn.x86_const.UC_X86_REG_RIP}
                if self.filetype == "PE":
                    self.tilName = "mssdk_win7"
                    self.regs.update({"arg1": unicorn.x86_const.UC_X86_REG_RCX,
                                      "arg2": unicorn.x86_const.UC_X86_REG_RDX,
                                      "arg3": unicorn.x86_const.UC_X86_REG_R8,
                                      "arg4": unicorn.x86_const.UC_X86_REG_R9})
                elif self.filetype == "MACHO":
                    self.tilName = "macosx64"
                    self.regs.update({"arg1": unicorn.x86_const.UC_X86_REG_RDI,
                                      "arg2": unicorn.x86_const.UC_X86_REG_RSI,
                                      "arg3": unicorn.x86_const.UC_X86_REG_RDX,
                                      "arg4": unicorn.x86_const.UC_X86_REG_RCX})
                elif self.filetype == "ELF":
                    self.tilName = "gnulnx_x64"
                    self.regs.update({"arg1": unicorn.x86_const.UC_X86_REG_RDI,
                                      "arg2": unicorn.x86_const.UC_X86_REG_RSI,
                                      "arg3": unicorn.x86_const.UC_X86_REG_RDX,
                                      "arg4": unicorn.x86_const.UC_X86_REG_RCX})
                else:
                    self.filetype = "UNKNOWN"
                    # assume PE for mem dumps
                    self.regs.update({"arg1": unicorn.x86_const.UC_X86_REG_RCX,
                                      "arg2": unicorn.x86_const.UC_X86_REG_RDX,
                                      "arg3": unicorn.x86_const.UC_X86_REG_R8,
                                      "arg4": unicorn.x86_const.UC_X86_REG_R9})
            elif bitness == 32:
                if self.filetype == "PE":
                    self.tilName = "mssdk"
                elif self.filetype == "MACHO":
                    self.tilName = "macosx"
                elif self.filetype == "ELF":
                    self.tilName = "gnulnx_x86"
                else:
                    self.filetype = "UNKNOWN"
                self.mode = unicorn.UC_MODE_32
                self.derefPtr = self.analysisHelper.getDwordValue
                mode = "32-bit"
                self.size_pointer = 4
                self.pack_fmt = "<I"
                self.pack_fmt_signed = "<i"
                self.pageMask = 0xfffff000
                self.regs = {"ax": unicorn.x86_const.UC_X86_REG_EAX, "bx": unicorn.x86_const.UC_X86_REG_EBX,
                             "cx": unicorn.x86_const.UC_X86_REG_ECX, "dx": unicorn.x86_const.UC_X86_REG_EDX,
                             "di": unicorn.x86_const.UC_X86_REG_EDI, "si": unicorn.x86_const.UC_X86_REG_ESI,
                             "bp": unicorn.x86_const.UC_X86_REG_EBP, "sp": unicorn.x86_const.UC_X86_REG_ESP,
                             "ip": unicorn.x86_const.UC_X86_REG_EIP, "pc": unicorn.x86_const.UC_X86_REG_EIP,
                             "eax": unicorn.x86_const.UC_X86_REG_EAX, "ebx": unicorn.x86_const.UC_X86_REG_EBX,
                             "ecx": unicorn.x86_const.UC_X86_REG_ECX, "edx": unicorn.x86_const.UC_X86_REG_EDX,
                             "edi": unicorn.x86_const.UC_X86_REG_EDI, "esi": unicorn.x86_const.UC_X86_REG_ESI,
                             "ebp": unicorn.x86_const.UC_X86_REG_EBP, "esp": unicorn.x86_const.UC_X86_REG_ESP,
                             "ret": unicorn.x86_const.UC_X86_REG_EAX}
            
            else:
                self.logger.error(
                    "sample contains code for unsupported processor architecture")
                return
        elif arch == "ARM":
            self.mode = unicorn.UC_MODE_ARM
            mode = "ARM"
            if bitness == 64:
                self.arch = unicorn.UC_ARCH_ARM64
                arch = "ARM64"
                if self.analysisHelper.getFileType() == "PE":
                    self.filetype = "PE"
                    self.tilName = "mssdk_win7"
                elif self.analysisHelper.getFileType() == "MACHO":
                    self.filetype = "MACHO"
                    self.tilName = "macosx64"
                elif self.analysisHelper.getFileType() == "ELF":
                    self.filetype = "ELF"
                    self.tilName = "gnulnx_x64"
                else:
                    self.filetype = "UNKNOWN"
                self.size_pointer = 8
                self.pack_fmt = "<Q"
                self.pack_fmt_signed = "<q"
                self.derefPtr = self.analysisHelper.getQWordValue
                self.pageMask = 0xfffffffffffff000
                self.regs = {"R0": unicorn.arm64_const.UC_ARM64_REG_X0, "R1": unicorn.arm64_const.UC_ARM64_REG_X1,
                             "R2": unicorn.arm64_const.UC_ARM64_REG_X2, "R3": unicorn.arm64_const.UC_ARM64_REG_X3,
                             "R4": unicorn.arm64_const.UC_ARM64_REG_X4, "R5": unicorn.arm64_const.UC_ARM64_REG_X5,
                             "R6": unicorn.arm64_const.UC_ARM64_REG_X6, "R7": unicorn.arm64_const.UC_ARM64_REG_X7,
                             "R8": unicorn.arm64_const.UC_ARM64_REG_X8, "R9": unicorn.arm64_const.UC_ARM64_REG_X9,
                             "R10": unicorn.arm64_const.UC_ARM64_REG_X10, "R11": unicorn.arm64_const.UC_ARM64_REG_X11,
                             "R12": unicorn.arm64_const.UC_ARM64_REG_X12, "R13": unicorn.arm64_const.UC_ARM64_REG_X13,
                             "R14": unicorn.arm64_const.UC_ARM64_REG_X14, "R15": unicorn.arm64_const.UC_ARM64_REG_X15,
                             "X0": unicorn.arm64_const.UC_ARM64_REG_X0, "X1": unicorn.arm64_const.UC_ARM64_REG_X1,
                             "X2": unicorn.arm64_const.UC_ARM64_REG_X2, "X3": unicorn.arm64_const.UC_ARM64_REG_X3,
                             "X4": unicorn.arm64_const.UC_ARM64_REG_X4, "X5": unicorn.arm64_const.UC_ARM64_REG_X5,
                             "X6": unicorn.arm64_const.UC_ARM64_REG_X6, "X7": unicorn.arm64_const.UC_ARM64_REG_X7,
                             "X8": unicorn.arm64_const.UC_ARM64_REG_X8, "X9": unicorn.arm64_const.UC_ARM64_REG_X9,
                             "X10": unicorn.arm64_const.UC_ARM64_REG_X10, "X11": unicorn.arm64_const.UC_ARM64_REG_X11,
                             "X12": unicorn.arm64_const.UC_ARM64_REG_X12, "X13": unicorn.arm64_const.UC_ARM64_REG_X13,
                             "X14": unicorn.arm64_const.UC_ARM64_REG_X14, "X15": unicorn.arm64_const.UC_ARM64_REG_X15,
                             "X16": unicorn.arm64_const.UC_ARM64_REG_X16, "X17": unicorn.arm64_const.UC_ARM64_REG_X17,
                             "X18": unicorn.arm64_const.UC_ARM64_REG_X18, "X19": unicorn.arm64_const.UC_ARM64_REG_X19,
                             "X20": unicorn.arm64_const.UC_ARM64_REG_X20, "X21": unicorn.arm64_const.UC_ARM64_REG_X21,
                             "X22": unicorn.arm64_const.UC_ARM64_REG_X22, "X23": unicorn.arm64_const.UC_ARM64_REG_X23,
                             "X24": unicorn.arm64_const.UC_ARM64_REG_X24, "X25": unicorn.arm64_const.UC_ARM64_REG_X25,
                             "X26": unicorn.arm64_const.UC_ARM64_REG_X26, "X27": unicorn.arm64_const.UC_ARM64_REG_X27,
                             "X28": unicorn.arm64_const.UC_ARM64_REG_X28, "X29": unicorn.arm64_const.UC_ARM64_REG_X29,
                             "X30": unicorn.arm64_const.UC_ARM64_REG_X30, "W0": unicorn.arm64_const.UC_ARM64_REG_X0,
                             "W1": unicorn.arm64_const.UC_ARM64_REG_X1, "W2": unicorn.arm64_const.UC_ARM64_REG_X2,
                             "W3": unicorn.arm64_const.UC_ARM64_REG_X3, "W4": unicorn.arm64_const.UC_ARM64_REG_X4,
                             "W5": unicorn.arm64_const.UC_ARM64_REG_X5, "W6": unicorn.arm64_const.UC_ARM64_REG_X6,
                             "W7": unicorn.arm64_const.UC_ARM64_REG_X7, "W8": unicorn.arm64_const.UC_ARM64_REG_X8,
                             "W9": unicorn.arm64_const.UC_ARM64_REG_X9, "W10": unicorn.arm64_const.UC_ARM64_REG_X10,
                             "W11": unicorn.arm64_const.UC_ARM64_REG_X11, "W12": unicorn.arm64_const.UC_ARM64_REG_X12,
                             "W13": unicorn.arm64_const.UC_ARM64_REG_X13, "W14": unicorn.arm64_const.UC_ARM64_REG_X14,
                             "W15": unicorn.arm64_const.UC_ARM64_REG_X15, "W16": unicorn.arm64_const.UC_ARM64_REG_X16,
                             "W17": unicorn.arm64_const.UC_ARM64_REG_X17, "W18": unicorn.arm64_const.UC_ARM64_REG_X18,
                             "W19": unicorn.arm64_const.UC_ARM64_REG_X19, "W20": unicorn.arm64_const.UC_ARM64_REG_X20,
                             "W21": unicorn.arm64_const.UC_ARM64_REG_X21, "W22": unicorn.arm64_const.UC_ARM64_REG_X22,
                             "W23": unicorn.arm64_const.UC_ARM64_REG_X23, "W24": unicorn.arm64_const.UC_ARM64_REG_X24,
                             "W25": unicorn.arm64_const.UC_ARM64_REG_X25, "W26": unicorn.arm64_const.UC_ARM64_REG_X26,
                             "W27": unicorn.arm64_const.UC_ARM64_REG_X27, "W28": unicorn.arm64_const.UC_ARM64_REG_X28,
                             "W29": unicorn.arm64_const.UC_ARM64_REG_X29, "W30": unicorn.arm64_const.UC_ARM64_REG_X30,
                             "PC": unicorn.arm64_const.UC_ARM64_REG_PC, "pc": unicorn.arm64_const.UC_ARM64_REG_PC,
                             "LR": unicorn.arm64_const.UC_ARM64_REG_X30, "SP": unicorn.arm64_const.UC_ARM64_REG_SP,
                             "sp": unicorn.arm64_const.UC_ARM64_REG_SP, "ret": unicorn.arm64_const.UC_ARM64_REG_X0,
                             "S0": unicorn.arm64_const.UC_ARM64_REG_S0, "S1": unicorn.arm64_const.UC_ARM64_REG_S1,
                             "S2": unicorn.arm64_const.UC_ARM64_REG_S2, "S3": unicorn.arm64_const.UC_ARM64_REG_S3,
                             "S4": unicorn.arm64_const.UC_ARM64_REG_S4, "S5": unicorn.arm64_const.UC_ARM64_REG_S5,
                             "S6": unicorn.arm64_const.UC_ARM64_REG_S6, "S7": unicorn.arm64_const.UC_ARM64_REG_S7,
                             "S8": unicorn.arm64_const.UC_ARM64_REG_S8, "S9": unicorn.arm64_const.UC_ARM64_REG_S9,
                             "S10": unicorn.arm64_const.UC_ARM64_REG_S10, "S11": unicorn.arm64_const.UC_ARM64_REG_S11,
                             "S12": unicorn.arm64_const.UC_ARM64_REG_S12, "S13": unicorn.arm64_const.UC_ARM64_REG_S13,
                             "S14": unicorn.arm64_const.UC_ARM64_REG_S14, "S15": unicorn.arm64_const.UC_ARM64_REG_S15,
                             "S16": unicorn.arm64_const.UC_ARM64_REG_S16, "S17": unicorn.arm64_const.UC_ARM64_REG_S17,
                             "S18": unicorn.arm64_const.UC_ARM64_REG_S18, "S19": unicorn.arm64_const.UC_ARM64_REG_S19,
                             "S20": unicorn.arm64_const.UC_ARM64_REG_S20, "S21": unicorn.arm64_const.UC_ARM64_REG_S21,
                             "S22": unicorn.arm64_const.UC_ARM64_REG_S22, "S23": unicorn.arm64_const.UC_ARM64_REG_S23,
                             "S24": unicorn.arm64_const.UC_ARM64_REG_S24, "S25": unicorn.arm64_const.UC_ARM64_REG_S25,
                             "S26": unicorn.arm64_const.UC_ARM64_REG_S26, "S27": unicorn.arm64_const.UC_ARM64_REG_S27,
                             "S28": unicorn.arm64_const.UC_ARM64_REG_S28, "S29": unicorn.arm64_const.UC_ARM64_REG_S29,
                             "S30": unicorn.arm64_const.UC_ARM64_REG_S30, "S31": unicorn.arm64_const.UC_ARM64_REG_S31,
                             "D0": unicorn.arm64_const.UC_ARM64_REG_D0, "D1": unicorn.arm64_const.UC_ARM64_REG_D1,
                             "D2": unicorn.arm64_const.UC_ARM64_REG_D2, "D3": unicorn.arm64_const.UC_ARM64_REG_D3,
                             "D4": unicorn.arm64_const.UC_ARM64_REG_D4, "D5": unicorn.arm64_const.UC_ARM64_REG_D5,
                             "D6": unicorn.arm64_const.UC_ARM64_REG_D6, "D7": unicorn.arm64_const.UC_ARM64_REG_D7,
                             "D8": unicorn.arm64_const.UC_ARM64_REG_D8, "D9": unicorn.arm64_const.UC_ARM64_REG_D9,
                             "D10": unicorn.arm64_const.UC_ARM64_REG_D10, "D11": unicorn.arm64_const.UC_ARM64_REG_D11,
                             "D12": unicorn.arm64_const.UC_ARM64_REG_D12, "D13": unicorn.arm64_const.UC_ARM64_REG_D13,
                             "D14": unicorn.arm64_const.UC_ARM64_REG_D14, "D15": unicorn.arm64_const.UC_ARM64_REG_D15,
                             "D16": unicorn.arm64_const.UC_ARM64_REG_D16, "D17": unicorn.arm64_const.UC_ARM64_REG_D17,
                             "D18": unicorn.arm64_const.UC_ARM64_REG_D18, "D19": unicorn.arm64_const.UC_ARM64_REG_D19,
                             "D20": unicorn.arm64_const.UC_ARM64_REG_D20, "D21": unicorn.arm64_const.UC_ARM64_REG_D21,
                             "D22": unicorn.arm64_const.UC_ARM64_REG_D22, "D23": unicorn.arm64_const.UC_ARM64_REG_D23,
                             "D24": unicorn.arm64_const.UC_ARM64_REG_D24, "D25": unicorn.arm64_const.UC_ARM64_REG_D25,
                             "D26": unicorn.arm64_const.UC_ARM64_REG_D26, "D27": unicorn.arm64_const.UC_ARM64_REG_D27,
                             "D28": unicorn.arm64_const.UC_ARM64_REG_D28, "D29": unicorn.arm64_const.UC_ARM64_REG_D29,
                             "D30": unicorn.arm64_const.UC_ARM64_REG_D30, "D31": unicorn.arm64_const.UC_ARM64_REG_D31,
                             "H0": unicorn.arm64_const.UC_ARM64_REG_H0, "H1": unicorn.arm64_const.UC_ARM64_REG_H1,
                             "H2": unicorn.arm64_const.UC_ARM64_REG_H2, "H3": unicorn.arm64_const.UC_ARM64_REG_H3,
                             "H4": unicorn.arm64_const.UC_ARM64_REG_H4, "H5": unicorn.arm64_const.UC_ARM64_REG_H5,
                             "H6": unicorn.arm64_const.UC_ARM64_REG_H6, "H7": unicorn.arm64_const.UC_ARM64_REG_H7,
                             "H8": unicorn.arm64_const.UC_ARM64_REG_H8, "H9": unicorn.arm64_const.UC_ARM64_REG_H9,
                             "H10": unicorn.arm64_const.UC_ARM64_REG_H10, "H11": unicorn.arm64_const.UC_ARM64_REG_H11,
                             "H12": unicorn.arm64_const.UC_ARM64_REG_H12, "H13": unicorn.arm64_const.UC_ARM64_REG_H13,
                             "H14": unicorn.arm64_const.UC_ARM64_REG_H14, "H15": unicorn.arm64_const.UC_ARM64_REG_H15,
                             "H16": unicorn.arm64_const.UC_ARM64_REG_H16, "H17": unicorn.arm64_const.UC_ARM64_REG_H17,
                             "H18": unicorn.arm64_const.UC_ARM64_REG_H18, "H19": unicorn.arm64_const.UC_ARM64_REG_H19,
                             "H20": unicorn.arm64_const.UC_ARM64_REG_H20, "H21": unicorn.arm64_const.UC_ARM64_REG_H21,
                             "H22": unicorn.arm64_const.UC_ARM64_REG_H22, "H23": unicorn.arm64_const.UC_ARM64_REG_H23,
                             "H24": unicorn.arm64_const.UC_ARM64_REG_H24, "H25": unicorn.arm64_const.UC_ARM64_REG_H25,
                             "H26": unicorn.arm64_const.UC_ARM64_REG_H26, "H27": unicorn.arm64_const.UC_ARM64_REG_H27,
                             "H28": unicorn.arm64_const.UC_ARM64_REG_H28, "H29": unicorn.arm64_const.UC_ARM64_REG_H29,
                             "H30": unicorn.arm64_const.UC_ARM64_REG_H30, "H31": unicorn.arm64_const.UC_ARM64_REG_H31,
                             "Q0": unicorn.arm64_const.UC_ARM64_REG_Q0, "Q1": unicorn.arm64_const.UC_ARM64_REG_Q1,
                             "Q2": unicorn.arm64_const.UC_ARM64_REG_Q2, "Q3": unicorn.arm64_const.UC_ARM64_REG_Q3,
                             "Q4": unicorn.arm64_const.UC_ARM64_REG_Q4, "Q5": unicorn.arm64_const.UC_ARM64_REG_Q5,
                             "Q6": unicorn.arm64_const.UC_ARM64_REG_Q6, "Q7": unicorn.arm64_const.UC_ARM64_REG_Q7,
                             "Q8": unicorn.arm64_const.UC_ARM64_REG_Q8, "Q9": unicorn.arm64_const.UC_ARM64_REG_Q9,
                             "Q10": unicorn.arm64_const.UC_ARM64_REG_Q10, "Q11": unicorn.arm64_const.UC_ARM64_REG_Q11,
                             "Q12": unicorn.arm64_const.UC_ARM64_REG_Q12, "Q13": unicorn.arm64_const.UC_ARM64_REG_Q13,
                             "Q14": unicorn.arm64_const.UC_ARM64_REG_Q14, "Q15": unicorn.arm64_const.UC_ARM64_REG_Q15,
                             "Q16": unicorn.arm64_const.UC_ARM64_REG_Q16, "Q17": unicorn.arm64_const.UC_ARM64_REG_Q17,
                             "Q18": unicorn.arm64_const.UC_ARM64_REG_Q18, "Q19": unicorn.arm64_const.UC_ARM64_REG_Q19,
                             "Q20": unicorn.arm64_const.UC_ARM64_REG_Q20, "Q21": unicorn.arm64_const.UC_ARM64_REG_Q21,
                             "Q22": unicorn.arm64_const.UC_ARM64_REG_Q22, "Q23": unicorn.arm64_const.UC_ARM64_REG_Q23,
                             "Q24": unicorn.arm64_const.UC_ARM64_REG_Q24, "Q25": unicorn.arm64_const.UC_ARM64_REG_Q25,
                             "Q26": unicorn.arm64_const.UC_ARM64_REG_Q26, "Q27": unicorn.arm64_const.UC_ARM64_REG_Q27,
                             "Q28": unicorn.arm64_const.UC_ARM64_REG_Q28, "Q29": unicorn.arm64_const.UC_ARM64_REG_Q29,
                             "Q30": unicorn.arm64_const.UC_ARM64_REG_Q30, "Q31": unicorn.arm64_const.UC_ARM64_REG_Q31,
                             "V0":unicorn.arm64_const.UC_ARM64_REG_V0,"V1":unicorn.arm64_const.UC_ARM64_REG_V1,
                             "V2":unicorn.arm64_const.UC_ARM64_REG_V2,"V3":unicorn.arm64_const.UC_ARM64_REG_V3,
                             "V4":unicorn.arm64_const.UC_ARM64_REG_V4,"V5":unicorn.arm64_const.UC_ARM64_REG_V5,
                             "V6":unicorn.arm64_const.UC_ARM64_REG_V6,"V7":unicorn.arm64_const.UC_ARM64_REG_V7,
                             "V8":unicorn.arm64_const.UC_ARM64_REG_V8,"V9":unicorn.arm64_const.UC_ARM64_REG_V9,
                             "V10":unicorn.arm64_const.UC_ARM64_REG_V10,"V11":unicorn.arm64_const.UC_ARM64_REG_V11,
                             "V12":unicorn.arm64_const.UC_ARM64_REG_V12,"V13":unicorn.arm64_const.UC_ARM64_REG_V13,
                             "V14":unicorn.arm64_const.UC_ARM64_REG_V14,"V15":unicorn.arm64_const.UC_ARM64_REG_V15,
                             "V16":unicorn.arm64_const.UC_ARM64_REG_V16,"V17":unicorn.arm64_const.UC_ARM64_REG_V17,
                             "V18":unicorn.arm64_const.UC_ARM64_REG_V18,"V19":unicorn.arm64_const.UC_ARM64_REG_V19,
                             "V20":unicorn.arm64_const.UC_ARM64_REG_V20,"V21":unicorn.arm64_const.UC_ARM64_REG_V21,
                             "V22":unicorn.arm64_const.UC_ARM64_REG_V22,"V23":unicorn.arm64_const.UC_ARM64_REG_V23,
                             "V24":unicorn.arm64_const.UC_ARM64_REG_V24,"V25":unicorn.arm64_const.UC_ARM64_REG_V25,
                             "V26":unicorn.arm64_const.UC_ARM64_REG_V26,"V27":unicorn.arm64_const.UC_ARM64_REG_V27,
                             "V28":unicorn.arm64_const.UC_ARM64_REG_V28,"V29":unicorn.arm64_const.UC_ARM64_REG_V29,
                             "V30":unicorn.arm64_const.UC_ARM64_REG_V30,"V31":unicorn.arm64_const.UC_ARM64_REG_V31}
                self.regs.update({"arg1": unicorn.arm64_const.UC_ARM64_REG_X0,
                                  "arg2": unicorn.arm64_const.UC_ARM64_REG_X1,
                                  "arg3": unicorn.arm64_const.UC_ARM64_REG_X2,
                                  "arg4": unicorn.arm64_const.UC_ARM64_REG_X3})
            elif bitness == 16 or bitness == 32:
                self.arch = unicorn.UC_ARCH_ARM
                arch = "ARM"
                if self.filetype == "PE":
                    self.tilName = "mssdk"
                elif self.filetype== "MACHO":
                    self.tilName = "macosx"
                elif self.filetype == "ELF":
                    self.tilName = "gnulnx_x86"
                else:
                    self.filetype = "UNKNOWN"

                self.size_pointer = 4
                self.pack_fmt = "<I"
                self.pack_fmt_signed = "<i"
                self.derefPtr = self.analysisHelper.getDwordValue
                self.pageMask = 0xfffff000
                self.regs = {"R0": unicorn.arm_const.UC_ARM_REG_R0, "R1": unicorn.arm_const.UC_ARM_REG_R1,
                             "R2": unicorn.arm_const.UC_ARM_REG_R2, "R3": unicorn.arm_const.UC_ARM_REG_R3,
                             "R4": unicorn.arm_const.UC_ARM_REG_R4, "R5": unicorn.arm_const.UC_ARM_REG_R5,
                             "R6": unicorn.arm_const.UC_ARM_REG_R6, "R7": unicorn.arm_const.UC_ARM_REG_R7,
                             "R8": unicorn.arm_const.UC_ARM_REG_R8, "R9": unicorn.arm_const.UC_ARM_REG_R9,
                             "R10": unicorn.arm_const.UC_ARM_REG_R10, "R11": unicorn.arm_const.UC_ARM_REG_R11,
                             "R12": unicorn.arm_const.UC_ARM_REG_R12, "R13": unicorn.arm_const.UC_ARM_REG_R13,
                             "R14": unicorn.arm_const.UC_ARM_REG_R14, "R15": unicorn.arm_const.UC_ARM_REG_R15,
                             "PC": unicorn.arm_const.UC_ARM_REG_R15, "pc": unicorn.arm_const.UC_ARM_REG_R15,
                             "LR": unicorn.arm_const.UC_ARM_REG_R14, "SP": unicorn.arm_const.UC_ARM_REG_R13,
                             "sp": unicorn.arm_const.UC_ARM_REG_R13, "apsr": unicorn.arm_const.UC_ARM_REG_APSR,
                             "APSR": unicorn.arm_const.UC_ARM_REG_APSR, "ret": unicorn.arm_const.UC_ARM_REG_R0,
                             "S0": unicorn.arm_const.UC_ARM_REG_S0, "S1": unicorn.arm_const.UC_ARM_REG_S1,
                             "S2": unicorn.arm_const.UC_ARM_REG_S2, "S3": unicorn.arm_const.UC_ARM_REG_S3,
                             "S4": unicorn.arm_const.UC_ARM_REG_S4, "S5": unicorn.arm_const.UC_ARM_REG_S5,
                             "S6": unicorn.arm_const.UC_ARM_REG_S6, "S7": unicorn.arm_const.UC_ARM_REG_S7,
                             "S8": unicorn.arm_const.UC_ARM_REG_S8, "S9": unicorn.arm_const.UC_ARM_REG_S9,
                             "S10": unicorn.arm_const.UC_ARM_REG_S10, "S11": unicorn.arm_const.UC_ARM_REG_S11,
                             "S12": unicorn.arm_const.UC_ARM_REG_S12, "S13": unicorn.arm_const.UC_ARM_REG_S13,
                             "S14": unicorn.arm_const.UC_ARM_REG_S14, "S15": unicorn.arm_const.UC_ARM_REG_S15,
                             "S16": unicorn.arm_const.UC_ARM_REG_S16, "S17": unicorn.arm_const.UC_ARM_REG_S17,
                             "S18": unicorn.arm_const.UC_ARM_REG_S18, "S19": unicorn.arm_const.UC_ARM_REG_S19,
                             "S20": unicorn.arm_const.UC_ARM_REG_S20, "S21": unicorn.arm_const.UC_ARM_REG_S21,
                             "S22": unicorn.arm_const.UC_ARM_REG_S22, "S23": unicorn.arm_const.UC_ARM_REG_S23,
                             "S24": unicorn.arm_const.UC_ARM_REG_S24, "S25": unicorn.arm_const.UC_ARM_REG_S25,
                             "S26": unicorn.arm_const.UC_ARM_REG_S26, "S27": unicorn.arm_const.UC_ARM_REG_S27,
                             "S28": unicorn.arm_const.UC_ARM_REG_S28, "S29": unicorn.arm_const.UC_ARM_REG_S29,
                             "S30": unicorn.arm_const.UC_ARM_REG_S30, "S31": unicorn.arm_const.UC_ARM_REG_S31}
                self.regs.update({"arg1": unicorn.arm_const.UC_ARM_REG_R0, "arg2": unicorn.arm_const.UC_ARM_REG_R1,
                                  "arg3": unicorn.arm_const.UC_ARM_REG_R2, "arg4": unicorn.arm_const.UC_ARM_REG_R3})
            else:
                self.logger.error(
                    "sample contains code for unsupported processor architecture")
                return
        else:
            self.logger.error(
                "sample contains code for unsupported processor architecture")
            return

        # naive API hooks
        self.apiHooks = {}
        self.apiHooks["GetProcessHeap"] = flare_emu_hooks._returnHandleHook
        self.apiHooks["HeapCreate"] = flare_emu_hooks._returnHandleHook
        self.apiHooks["HeapAlloc"] = flare_emu_hooks._allocMem3Hook
        self.apiHooks["HeapReAlloc"] = flare_emu_hooks._heapReAllocHook
        self.apiHooks["RtlAllocateHeap"] = flare_emu_hooks._allocMem3Hook
        self.apiHooks["AllocateHeap"] = flare_emu_hooks._allocMem1Hook
        
        # ignore LMEM_MOVEABLE flag, return mem ptr anyway, have Lock return ptr param
        self.apiHooks["LocalAlloc"] = flare_emu_hooks._allocMem2Hook
        self.apiHooks["LocalLock"] = flare_emu_hooks._returnParam1Hook
        self.apiHooks["GlobalAlloc"] = flare_emu_hooks._allocMem2Hook
        self.apiHooks["GlobalLock"] = flare_emu_hooks._returnParam1Hook
        
        # these ignore flags for now
        self.apiHooks["LocalReAlloc"] = flare_emu_hooks._reallocHook
        self.apiHooks["GlobalReAlloc"] = flare_emu_hooks._reallocHook
        
        self.apiHooks["VirtualAlloc"] = flare_emu_hooks._virtualAllocHook
        self.apiHooks["VirtualAllocEx"] = flare_emu_hooks._virtualAllocExHook
        self.apiHooks["malloc"] = flare_emu_hooks._allocMem1Hook
        self.apiHooks["calloc"] = flare_emu_hooks._callocHook
        self.apiHooks["realloc"] = flare_emu_hooks._reallocHook
        self.apiHooks["memcpy"] = flare_emu_hooks._memcpyHook
        self.apiHooks["memmove"] = flare_emu_hooks._memcpyHook
        self.apiHooks["strlen"] = flare_emu_hooks._strlenHook
        self.apiHooks["lstrlenA"] = flare_emu_hooks._strlenHook
        self.apiHooks["strnlen"] = flare_emu_hooks._strnlenHook
        self.apiHooks["strnlen_s"] = flare_emu_hooks._strnlenHook
        self.apiHooks["strcmp"] = flare_emu_hooks._strcmpHook
        self.apiHooks["lstrcmpA"] = flare_emu_hooks._strcmpHook
        self.apiHooks["strncmp"] = flare_emu_hooks._strncmpHook
        self.apiHooks["stricmp"] = flare_emu_hooks._stricmpHook
        self.apiHooks["lstrcmpiA"] = flare_emu_hooks._stricmpHook
        self.apiHooks["strnicmp"] = flare_emu_hooks._strnicmpHook
        self.apiHooks["wcscmp"] = flare_emu_hooks._wcscmpHook
        self.apiHooks["lstrcmpW"] = flare_emu_hooks._wcscmpHook
        self.apiHooks["wcsncmp"] = flare_emu_hooks._wcsncmpHook
        self.apiHooks["wcsicmp"] = flare_emu_hooks._wcsicmpHook
        self.apiHooks["lstrcmpiW"] = flare_emu_hooks._wcsicmpHook
        self.apiHooks["wcsnicmp"] = flare_emu_hooks._wcsnicmpHook
        self.apiHooks["mbscmp"] = flare_emu_hooks._strcmpHook
        self.apiHooks["mbsncmp"] = flare_emu_hooks._strncmpHook
        self.apiHooks["mbsicmp"] = flare_emu_hooks._stricmpHook
        self.apiHooks["mbsnicmp"] = flare_emu_hooks._strnicmpHook
        self.apiHooks["strcpy"] = flare_emu_hooks._strcpyHook
        self.apiHooks["strncpy"] = flare_emu_hooks._strncpyHook
        self.apiHooks["lstrcpyA"] = flare_emu_hooks._strcpyHook
        self.apiHooks["lstrcpynA"] = flare_emu_hooks._strncpyHook
        self.apiHooks["strncpy_s"] = flare_emu_hooks._strncpysHook
        self.apiHooks["wcscpy"] = flare_emu_hooks._wcscpyHook
        self.apiHooks["wcsncpy"] = flare_emu_hooks._wcsncpyHook
        self.apiHooks["lstrcpyW"] = flare_emu_hooks._wcscpyHook
        self.apiHooks["lstrcpynW"] = flare_emu_hooks._wcsncpyHook
        self.apiHooks["wcsncpy_s"] = flare_emu_hooks._wcsncpysHook
        self.apiHooks["mbscpy"] = flare_emu_hooks._strcpyHook
        self.apiHooks["mbsncpy"] = flare_emu_hooks._strncpyHook
        self.apiHooks["mbsncpy_s"] = flare_emu_hooks._strncpysHook
        self.apiHooks["memchr"] = flare_emu_hooks._memchrHook
        self.apiHooks["strchr"] = flare_emu_hooks._strchrHook
        self.apiHooks["wcschr"] = flare_emu_hooks._wcschrHook
        self.apiHooks["mbschr"] = flare_emu_hooks._strchrHook
        self.apiHooks["strrchr"] = flare_emu_hooks._strrchrHook
        self.apiHooks["wcsrchr"] = flare_emu_hooks._wcsrchrHook
        self.apiHooks["mbsrchr"] = flare_emu_hooks._strrchrHook
        self.apiHooks["wcslen"] = flare_emu_hooks._wcslenHook
        self.apiHooks["lstrlenW"] = flare_emu_hooks._wcslenHook
        self.apiHooks["mbslen"] = flare_emu_hooks._strlenHook
        self.apiHooks["mbstrlen"] = flare_emu_hooks._strlenHook
        self.apiHooks["wcsnlen"] = flare_emu_hooks._wcsnlenHook
        self.apiHooks["wcsnlen_s"] = flare_emu_hooks._wcsnlenHook
        self.apiHooks["mbsnlen"] = flare_emu_hooks._strnlenHook
        self.apiHooks["mbstrnlen"] = flare_emu_hooks._strnlenHook
        self.apiHooks["strcat"] = flare_emu_hooks._strcatHook
        self.apiHooks["lstrcatA"] = flare_emu_hooks._strcatHook
        self.apiHooks["strncat"] = flare_emu_hooks._strncatHook
        self.apiHooks["wcscat"] = flare_emu_hooks._wcscatHook
        self.apiHooks["lstrcatW"] = flare_emu_hooks._wcscatHook
        self.apiHooks["wcsncat"] = flare_emu_hooks._wcsncatHook
        self.apiHooks["mbscat"] = flare_emu_hooks._strcatHook
        self.apiHooks["mbsncat"] = flare_emu_hooks._strncatHook
        self.apiHooks["strlwr"] = flare_emu_hooks._strlwrHook
        self.apiHooks["strupr"] = flare_emu_hooks._struprHook
        self.apiHooks["wcslwr"] = flare_emu_hooks._wcslwrHook
        self.apiHooks["wcsupr"] = flare_emu_hooks._wcsuprHook
        self.apiHooks["mbslwr"] = flare_emu_hooks._strlwrHook
        self.apiHooks["mbsupr"] = flare_emu_hooks._struprHook
        self.apiHooks["strdup"] = flare_emu_hooks._strdupHook
        self.apiHooks["wcsdup"] = flare_emu_hooks._wcsdupHook
        self.apiHooks["mbsdup"] = flare_emu_hooks._strdupHook
        self.apiHooks["mbtowc"] = flare_emu_hooks._mbtowcHook
        self.apiHooks["mbstowcs"] = flare_emu_hooks._mbstowcsHook
        self.apiHooks["wctomb"] = flare_emu_hooks._wctombHook
        self.apiHooks["wcstombs"] = flare_emu_hooks._wcstombsHook
        self.apiHooks["MultiByteToWideChar"] = flare_emu_hooks._multiByteToWideCharHook
        self.apiHooks["WideCharToMultiByte"] = flare_emu_hooks._wideCharToMultiByteHook
        self.apiHooks["memset"] = flare_emu_hooks._memsetHook
        self.apiHooks["ZeroMemory"] = flare_emu_hooks._bzeroHook
        self.apiHooks["bzero"] = flare_emu_hooks._bzeroHook
        
        # builtins
        self.apiHooks["umodsi3"] = flare_emu_hooks._modHook
        
        self.allocMap = {}
        
        # Initialize emulator
        mu = unicorn.Uc(self.arch, self.mode)
        self.logger.info("initialized emulator for %s with %s architecture in %s mode" % (
            self.filetype, arch, mode))
        self.uc = mu
        if self.arch == unicorn.UC_ARCH_ARM or self.arch == unicorn.UC_ARCH_ARM64:
            self._enableVFP()

    # adds a new API hook to EmuHelper
    # apiName: name of the function to hook as it is named in binary analysis tool
    # hook: can be a string for the name of an existing hooked API, in which case this new hook
    # will use the same hook function
    # hook: can alternatively be a hook function you have defined
    def addApiHook(self, apiName, hook):
        if isinstance(hook, str):
            if hook in self.apiHooks:
                self.apiHooks[apiName] = self.apiHooks[hook]
            else:
                self.logger.error("%s is not a currently defined API hook" % hook)
                return False
        elif isinstance(hook, types.FunctionType):
            self.apiHooks[apiName] = hook
            return True
        else:
            self.logger.error("unsupported hook type")
            return False
    
    # unmap all emulator memory
    def resetEmulatorMemory(self):
        self.allocMap = {}
        for region in self.uc.mem_regions():
            self.uc.mem_unmap(region[0], region[1] - region[0] + 1)

    def resetEmulatorHeapAndStack(self):
        for region in self.uc.mem_regions():
            if region[0] != self.baseAddr:
                self.uc.mem_unmap(region[0], region[1] - region[0] + 1)
                self.logger.debug("unmapped %s to %s" % (
                    self.hexString(region[0]), self.hexString(region[1])))
        self._buildStack()

    # reset emulator memory and rewrite binary segments to emulator memory, build new stack
    def reloadBinary(self):
        self.resetEmulatorMemory()
        baseAddr = self.analysisHelper.getMinimumAddr()
        endAddr = self.analysisHelper.getMaximumAddr()
        self.baseAddr = baseAddr
        memsize = endAddr - baseAddr
        memsize = self.pageAlignUp(memsize) + PAGESIZE
        self.logger.debug("base addr: %s end addr: %s memsize: %s" % (self.hexString(baseAddr), 
                      self.hexString(endAddr), self.hexString(memsize)))
        # map all binary segments as one memory region for easier management
        self.uc.mem_map(baseAddr & self.pageMask, memsize)
        for segVA in self.analysisHelper.getSegments():
            # we don't want to map PAGEZERO
            if self.filetype == "MACHO" and segVA == 0:
                continue
            segName = self.analysisHelper.getSegmentName(segVA)
            endVA = self.analysisHelper.getSegmentEnd(segVA)
            segSizeTotal = endVA - segVA
            segSize = self.analysisHelper.getSegmentDefinedSize(segVA)
            self.logger.debug("bytes in seg: %s" % self.hexString(segSize))
            self.logger.debug("mapping segment %s: %s - %s" %
                          (segName, self.hexString(segVA), self.hexString(endVA)))
            if segSize > 0:
                segBytes = self.analysisHelper.getBytes(segVA, segSize)
                self.writeEmuMem(segVA, segBytes)
            segLeftover = segSizeTotal - segSize
            if segLeftover > 0:
                self.writeEmuMem(segVA + segSize, b"\x00" * segLeftover)
        self._buildStack()

    # allocs mem and writes bytes into it
    def loadBytes(self, bytes, addr=None):
        mem = self.allocEmuMem(len(bytes), addr)
        self.writeEmuMem(mem, bytes)
        return mem

    def isValidEmuPtr(self, ptr):
        for region in self.uc.mem_regions():
            if ptr >= region[0] and ptr < region[1]:
                return True
        return False
        
    def getEmuMemRegion(self, addr):
        for region in self.uc.mem_regions():
            if addr >= region[0] and addr < region[1]:
                return (region[0], region[1] + 1)
        return None
        
    # allocate emulator memory, attempts to honor specified address, otherwise begins allocations 
    # at an available page
    # aligned address, returns address, rebased if necessary
    def allocEmuMem(self, size, addr=None):
        allocSize = self.pageAlignUp(size)
        fail = False
        if addr is None or addr == 0:
            baseAddr = addr = self._findUnusedMemRegion(size)
            if baseAddr is None:
                
                fail = True
        else:
            baseAddr = self.pageAlign(addr)
            offs = addr - baseAddr
            if self._regionOverlapsWithExistingRegion(baseAddr, allocSize):
                baseAddr = self._findUnusedMemRegion(size)
                if baseAddr is None:
                    fail = True
                else:
                    addr = baseAddr + offs

        if not fail:
            self.logger.debug("mapping %s bytes @%s" %
                          (self.hexString(allocSize), self.hexString(baseAddr)))
            self.uc.mem_map(baseAddr, allocSize)
            return addr

        return None
     
    
    def copyEmuMem(self, dstAddr, srcAddr, size, userData):
        size = self._checkMemSize(size, userData)
        try:
            mem = self.uc.mem_read(srcAddr, size)
            self.writeEmuMem(dstAddr, mem)
        except Exception as e:
            self.logger.error("exception in copyEmuMem @%s: %s" % (self.hexString(userData["currAddr"]), str(e)))
        
    def getCallTargetName(self, address):
        if self.analysisHelper.getOpndType(address, 0) == self.analysisHelper.o_reg:
            funcName = self.analysisHelper.getName(self.getRegVal(self.analysisHelper.getOperand(address, 0)))
        else:
            funcName = self.analysisHelper.getName(self.analysisHelper.getOpndValue(address, 0))
        return self.analysisHelper.normalizeFuncName(funcName)
    
    # we don't know the number of args to a given function and we're not considering SSE args
    # this is just a convenience, use the emulator object if you have specific needs
    def getArgv(self):
        if self.arch == unicorn.UC_ARCH_X86:
            if self.mode == unicorn.UC_MODE_64:
                sp = self.getRegVal("rsp")
                # ensure there is mem mapped at the stack pointer
                try:
                    self.uc.mem_read(sp, 4)
                except:
                    sp = self.allocEmuMem(0x2000) + 0x1000
                    self.uc.reg_write(self.regs["sp"], sp)

                if self.filetype == "MACHO" or self.filetype == "ELF":
                    argv = [
                        self.getRegVal("rdi"),
                        self.getRegVal("rsi"),
                        self.getRegVal("rdx"),
                        self.getRegVal("rcx"),
                        self.getRegVal("r8"),
                        self.getRegVal("r9"),
                        struct.unpack("<Q", self.uc.mem_read(sp, 8))[0],
                        struct.unpack("<Q", self.uc.mem_read(sp + 8, 8))[0]]
                else:
                    argv = [
                        self.getRegVal("rcx"),
                        self.getRegVal("rdx"),
                        self.getRegVal("r8"),
                        self.getRegVal("r9"),
                        struct.unpack("<Q", self.uc.mem_read(sp + 32, 8))[0],
                        struct.unpack("<Q", self.uc.mem_read(sp + 40, 8))[0],
                        struct.unpack("<Q", self.uc.mem_read(sp + 48, 8))[0],
                        struct.unpack("<Q", self.uc.mem_read(sp + 56, 8))[0]]
            else:
                sp = self.getRegVal("esp")
                argv = [
                    struct.unpack("<I", self.uc.mem_read(sp, 4))[0],
                    struct.unpack("<I", self.uc.mem_read(sp + 4, 4))[0],
                    struct.unpack("<I", self.uc.mem_read(sp + 8, 4))[0],
                    struct.unpack("<I", self.uc.mem_read(sp + 12, 4))[0],
                    struct.unpack("<I", self.uc.mem_read(sp + 16, 4))[0],
                    struct.unpack("<I", self.uc.mem_read(sp + 20, 4))[0],
                    struct.unpack("<I", self.uc.mem_read(sp + 24, 4))[0],
                    struct.unpack("<I", self.uc.mem_read(sp + 28, 4))[0]]
        elif self.arch == unicorn.UC_ARCH_ARM:
            sp = self.getRegVal("SP")
            argv = [
                self.getRegVal("R0"),
                self.getRegVal("R1"),
                self.getRegVal("R2"),
                self.getRegVal("R3"),
                struct.unpack("<I", self.uc.mem_read(sp, 4))[0],
                struct.unpack("<I", self.uc.mem_read(sp + 4, 4))[0],
                struct.unpack("<I", self.uc.mem_read(sp + 8, 4))[0],
                struct.unpack("<I", self.uc.mem_read(sp + 12, 4))[0]]
        elif self.arch == unicorn.UC_ARCH_ARM64:
            argv = [
                self.getRegVal("X0"),
                self.getRegVal("X1"),
                self.getRegVal("X2"),
                self.getRegVal("X3"),
                self.getRegVal("X4"),
                self.getRegVal("X5"),
                self.getRegVal("X6"),
                self.getRegVal("X7")]
        else:
            argv = None
                
        return argv
 
    def _checkMemSize(self, size, userData):
        if size > MAX_ALLOC_SIZE:
            self.logger.debug("allocation size (%s) truncated @%s" % 
                          (self.hexString(size), self.hexString(userData["currAddr"])))
            size = MAX_ALLOC_SIZE
        return size
        
    # maps null memory as requested during emulation
    def _hookMemInvalid(self, uc, access, address, size, value, userData):
        self.logger.debug("invalid memory operation for %s @%s" %
                      (self.hexString(address), self.hexString(userData['currAddr'])))
        try:
            uc.mem_map(address & self.pageMask, PAGESIZE)
            self.writeEmuMem(address & self.pageMask, b"\x00" * PAGESIZE)
            self.logger.debug("allocated memory to %s" % self.hexString(address))
        except Exception:
            self.logger.debug("error writing to %s, changing IP from %s to %s" % (self.hexString(address), self.hexString(
                userData['currAddr']), self.hexString(userData['currAddr'] + userData['currAddrSize'])))
            userData['EmuHelper'].skipInstruction(userData)
        return True

    # cannot seem to move IP forward from this hook for some reason..
    # patches current instruction with NOPs
    def _hookInterrupt(self, uc, intno, userData):
        self.logger.debug("interrupt #%d received @%s" % ((intno), self.hexString(userData["currAddr"])))
        if self.arch == unicorn.UC_ARCH_X86:
            self.writeEmuMem(userData["currAddr"], X86NOP *
                         int(userData["currAddrSize"]))
        elif self.arch == unicorn.UC_ARCH_ARM:
            if self.mode == unicorn.UC_MODE_THUMB:
                self.writeEmuMem(userData["currAddr"],
                             ARMTHUMBNOP * int((userData["currAddrSize"] / 2)))
            else:
                self.writeEmuMem(
                    userData["currAddr"], ARMNOP * int((userData["currAddrSize"] / 4)))
        elif self.arch == unicorn.UC_ARCH_ARM64:
            self.writeEmuMem(
                userData["currAddr"], ARM64NOP * int((userData["currAddrSize"] / 4)))
        self.enteredBlock = False
        return True

    def normalizeApiName(self, funcName):
        if funcName[:2] == "j_":
            funcName = funcName[2:]
            
        # remove appended _l for locale flavors of string functions
        funcName = re.sub(r"_l$", "", funcName)
        
        # remove prepended underscores
        funcName = re.sub(r"^_+", "", funcName)
      
        return funcName
        
    # handle common runtime functions
    def _handleApiHooks(self, address, argv, funcName, userData):
        if funcName not in self.apiHooks:
            funcName = self.normalizeApiName(funcName)
            if funcName not in self.apiHooks:
                return False
        try:
            self.apiHooks[funcName](self, address, argv, funcName, userData)
        except Exception as e:
            self.logger.error("error handling API hook: %s @%s" % (e, self.hexString(address)))
            
        self.skipInstruction(userData)
        return True
    
    # instruction hook used by emulateRange function
    # implements bare bones instrumentation to handle basic code flow
    def _emulateRangeCodeHook(self, uc, address, size, userData):
        try:
            userData['currAddr'] = address
            userData['currAddrSize'] = size
            if self.arch == unicorn.UC_ARCH_ARM and userData["changeThumbMode"]:
                self._handleThumbMode(address)
                userData["changeThumbMode"] = False
                return

            # if strict mode is disabled, make instructions as we go as needed
            if not userData.get("strict", True):
                if self.analysisHelperFramework in ["Rizin", "Radare2"] or self.analysisHelper.getMnem(address) == "":
                    self.analysisHelper.makeInsn(address)
            
            if self.verbose > 0:
                if self.verbose > 1:
                    self.logger.debug(self.getEmuState())
                dis = self.analysisHelper.getDisasmLine(address)
                self.logger.debug("%s: %s" % (self.hexString(address), dis))

            # stop emulation if specified endAddr is reached
            if userData.get("endAddr", None) is not None:
                if address == userData["endAddr"]:
                    self.stopEmulation(userData)
                    return
            if userData.get("strict", True) and self._isBadBranch(userData):
                self.skipInstruction(userData)
                return
            # stop annoying run ons if we end up somewhere we dont belong
            if self.uc.mem_read(address, size) == b"\x00" * size:
                self.logger.debug("pc ended up in null memory @%s" %
                              self.hexString(address))
                self.stopEmulation(userData)
                return

            # otherwise, stop emulation when returning from function emulation began in
            elif ("funcStart" in userData and self.isRetInstruction(address) and
                    self.analysisHelper.getFuncStart(address) ==
                    userData["funcStart"]):
                self.stopEmulation(userData)
                return
            elif self.isRetInstruction(address) and self.arch == unicorn.UC_ARCH_ARM:
                # check mode of return address if ARM
                #retAddr = self.getEmuPtr(self.getRegVal("LR"))
                #if self.analysisHelper.isThumbMode(retAddr):
                #    userData["changeThumbMode"] = True
                userData["changeThumbMode"] = True

            if (self.analysisHelper.getMnem(address).upper() in self.callMnems or
                    (self.analysisHelper.getMnem(address).upper() == "B" and
                     self.analysisHelper.getNameAddr(self.analysisHelper.getOperand(address, 0)) ==
                     self.analysisHelper.getFuncStart(
                        self.analysisHelper.getNameAddr(self.analysisHelper.getOperand(address, 0))))):
                        
                funcName = self.getCallTargetName(address)
                if userData["callHook"]:
                    userData["callHook"](address, self.getArgv(), funcName, userData)

                if self.arch == unicorn.UC_ARCH_ARM:
                    userData["changeThumbMode"] = True
                    
                # if the pc has been changed by the hook, don't skip instruction and undo the change
                if self.getRegVal("pc") != userData["currAddr"]:
                    # get SP delta value for next instruction to adjust stack accordingly since we are skipping this
                    # instruction
                    uc.reg_write(self.regs["sp"], self.getRegVal("sp") +
                                    self.analysisHelper.getSpDelta(self.getRegVal("pc")))
                    return
                 
                if userData["hookApis"] and self._handleApiHooks(address, self.getArgv(), funcName, userData):
                    return
                
                # skip calls if specified or there are no instructions to emulate at destination address
                if (userData["skipCalls"] is True or
                        (self.analysisHelper.getOpndType(address, 0) == self.analysisHelper.o_near and
                         uc.mem_read(self.analysisHelper.getOpndValue(address, 0), self.size_pointer) ==
                         b"\x00" * self.size_pointer)):
                    self.skipInstruction(userData)
            # handle x86 instructions moving import pointers to a register
            elif (self.analysisHelper.getMnem(address).lower() == "mov" and 
                  self.analysisHelper.getOpndType(address, 1) == self.analysisHelper.o_mem and 
                  self.analysisHelper.getOpndType(address, 0) == self.analysisHelper.o_reg and
                  (len(self.analysisHelper.getOperand(address, 0)) == 3 and
                  (self.analysisHelper.getOperand(address, 1)[:3] == "ds:" or 
                  "sym.imp." in self.analysisHelper.getOperand(address, 1)) and 
                  uc.mem_read(self.analysisHelper.getOpndValue(address, 1), self.size_pointer) ==
                  b"\x00" * self.size_pointer)):             
                  uc.reg_write(self.regs[self.analysisHelper.getOperand(address, 0)], 
                               self.analysisHelper.getOpndValue(address, 1))
                  self.skipInstruction(userData)

        except Exception as err:
            self.logger.error("exception in emulateRangeCodehook @%s: %s" % (self.hexString(address), str(err)))
            self.stopEmulation(userData)

    # instruction hook used by emulateBytes function
    # implements bare bones instrumentation to handle basic code flow
    def _emulateBytesCodeHook(self, uc, address, size, userData):
        try:
            userData['currAddr'] = address
            userData['currAddrSize'] = size
            # stop emulation if specified endAddr is reached
            if userData["endAddr"] is not None:
                if address == userData["endAddr"]:
                    self.stopEmulation(userData)
                    return

            # stop annoying run ons if we end up somewhere we dont belong
            if self.uc.mem_read(address, 0x10) == b"\x00" * 0x10:
                self.stopEmulation(userData)
                self.logger.debug("pc ended up in null memory @%s" %
                              self.hexString(address))
                return

        except Exception as err:
            self.logger.error("exception in emulateBytesCodehook @%s: %s" % (self.hexString(address), str(err)))
            self.stopEmulation(userData)

    # this instruction hook is used by the iterate feature, forces execution down a specified path
    def _guidedHook(self, uc, address, size, userData):
        
        try:
            userData['currAddr'] = address
            userData['currAddrSize'] = size
            if self.arch == unicorn.UC_ARCH_ARM and userData["changeThumbMode"]:
                self._handleThumbMode(address)
                userData["changeThumbMode"] = False
                return
            if self.verbose > 0:
                if self.verbose > 1:
                    self.logger.debug(self.getEmuState())
                dis = self.analysisHelper.getDisasmLine(address)
                self.logger.debug("%s: %s" % (self.hexString(address), dis))
            if self.arch == unicorn.UC_ARCH_ARM:
                # since there are lots of bad branches during emulation and we are forcing it anyways
                if self.analysisHelper.getMnem(address)[:3].upper() in ["TBB", "TBH"]:
                    # skip over interleaved jump table
                    nextInsnAddr = self.analysisHelper.skipJumpTable(address + size)
                    self.changeProgramCounter(userData, nextInsnAddr)
                    return
            elif userData.get("strict", True) and self._isBadBranch(userData):
                self.skipInstruction(userData)
                return

            flow, paths = userData["targetInfo"][userData["targetVA"]]
            # check if we are out of our block bounds or re-entering our block in a loop
            bbEnd = flow[paths[self.pathIdx][self.blockIdx]][1]
            bbStart = flow[paths[self.pathIdx][self.blockIdx]][0]
            if address == bbStart and self.enteredBlock is True:
                if self.blockIdx < len(paths[self.pathIdx]) - 1:
                    self.logger.debug("loop re-entering block #%d (%s -> %s), forcing PC to %s" %
                                  (self.blockIdx, self.hexString(bbStart), self.hexString(bbEnd),
                                   self.hexString(flow[paths[self.pathIdx][self.blockIdx + 1]][0])))
                    # force PC to follow paths
                    uc.reg_write(self.regs["pc"], flow[paths[self.pathIdx][self.blockIdx + 1]][0])
                    self.blockIdx += 1
                    self.enteredBlock = False
                    if self.arch == unicorn.UC_ARCH_ARM:
                        userData["changeThumbMode"] = True
                    return
                else:
                    self.logger.debug(
                        "loop re-entering block #%d (%s -> %s), but no more blocks! bailing out of this function.." %
                        (self.blockIdx, self.hexString(bbStart), self.hexString(bbEnd)))
                    self.stopEmulation(userData)
                    return
            elif (address > bbEnd or address < bbStart):
                # check if we skipped over our target (our next block index is out of range), this can happen in ARM
                # with conditional instructions
                if self.blockIdx + 1 >= len(paths[self.pathIdx]):
                    self.logger.debug(
                        "we missed our target! bailing out of this function..")
                    self.stopEmulation(userData)
                    return
                self.logger.debug("%s is outside of block #%d (%s -> %s), forcing PC to %s" %
                              (self.hexString(address),
                               self.blockIdx, self.hexString(bbStart),
                               self.hexString(bbEnd), 
                               self.hexString(flow[paths[self.pathIdx][self.blockIdx + 1]][0])))
                # force PC to follow paths
                uc.reg_write(self.regs["pc"], flow[paths[self.pathIdx][self.blockIdx + 1]][0])
                self.blockIdx += 1
                self.enteredBlock = False
                if self.arch == unicorn.UC_ARCH_ARM:
                    userData["changeThumbMode"] = True
                return
            
            if address == bbStart:
                self.enteredBlock = True
            # possibly a folded instruction or invalid instruction
            if self.analysisHelper.getMnem(address) == "":
                if self.analysisHelper.getMnem(address + size) == "":
                    if self.analysisHelper.getMnem(address + size * 2) == "":
                        self.logger.debug(
                            "invalid instruction encountered @%s, bailing.." % self.hexString(address))
                        self.stopEmulation(userData)
                    return
                return

            # stop annoying run ons if we end up somewhere we dont belong
            if self.uc.mem_read(address, 0x10) == b"\x00" * 0x10:
                self.logger.debug("pc ended up in null memory @%s" %
                              self.hexString(address))
                self.stopEmulation(userData)
                return
            
            # this is our stop, this is where we trigger user-defined callback with our info
            if address == userData["targetVA"]:
                self.logger.debug("target %s hit" %
                              self.hexString(userData["targetVA"]))
                self._targetHit(address, userData)
                self.stopEmulation(userData)
            elif address in userData["targetInfo"]:
                # this address is another target in the dict, process it and continue onward
                self.logger.debug("target %s found on the way to %s, processing" % (
                    self.hexString(address), self.hexString(userData["targetVA"])))
                self._targetHit(address, userData)

            if (self.analysisHelper.getMnem(address).upper() in self.callMnems or
                (self.analysisHelper.getMnem(address).upper() == "B" and
                 self.analysisHelper.getNameAddr(self.analysisHelper.getOperand(address, 0)) ==
                 self.analysisHelper.getFuncStart(
                 self.analysisHelper.getNameAddr(self.analysisHelper.getOperand(address, 0))))):
                
                funcName = self.getCallTargetName(address)
                if userData["callHook"]:
                    userData["callHook"](address, self.getArgv(), funcName, userData)

                if self.arch == unicorn.UC_ARCH_ARM:
                    userData["changeThumbMode"] = True

                # if the pc has been changed by the hook, don't skip instruction and undo the change
                if self.getRegVal("pc") != userData["currAddr"]:
                    # get SP delta value for next instruction to adjust stack accordingly since we are skipping this
                    # instruction
                    uc.reg_write(self.regs["sp"], self.getRegVal("sp") +
                                 self.analysisHelper.getSpDelta(self.getRegVal("pc")))
                    return
                
                if userData["hookApis"] and self._handleApiHooks(address, self.getArgv(), funcName, userData):
                    return
                    
                # if you change the program counter, it undoes your call to emu_stop()
                if address != userData["targetVA"]:
                    self.skipInstruction(userData)
                    
            elif self.isRetInstruction(address):
                # self.stopEmulation(userData)
                self.skipInstruction(userData)
                return

        except Exception as e:
            self.logger.error("exception in _guidedHook @%s: %s" % (self.hexString(address), e))
            self.stopEmulation(userData)


    # checks ARM mode for address and aligns address accordingly
    def _handleThumbMode(self, address):
        if self.analysisHelper.isThumbMode(address):
            self.uc.reg_write(self.regs["pc"], self.getRegVal("pc") | 1)
            self.mode = unicorn.UC_MODE_THUMB
        else:
            self.uc.reg_write(self.regs["pc"], self.getRegVal("pc") & ~1)
            self.mode = unicorn.UC_MODE_ARM

    # called when an iterate target is reached
    def _targetHit(self, address, userData):
        try:
            argv = self.getArgv()
            userData["targetCallback"](self, address, argv, userData)
        except Exception as e:
            self.logger.error("exception in targetCallback function @%s: %s" % (self.hexString(address), str(e)))
        userData["visitedTargets"].append(address)

    # this only works for IDA Pro since radare2 will always disassemble
    def _isBadBranch(self, userData):
        if self.arch == unicorn.UC_ARCH_ARM64:
            if (self.analysisHelper.getMnem(userData["currAddr"]).upper() in ["BR", "BREQ"] and
                    self.analysisHelper.getOpndType(userData["currAddr"], 0) == self.analysisHelper.o_reg):
                if (self.analysisHelper.getMnem(
                        self.getRegVal(self.analysisHelper.getOperand(userData["currAddr"], 0)
                        ))) == "":
                    return True
        elif self.arch == unicorn.UC_ARCH_X86:
            if (self.analysisHelper.getMnem(userData["currAddr"]).lower() == "jmp" and
                    self.analysisHelper.getOpndType(userData["currAddr"], 0) == self.analysisHelper.o_reg):
                if (self.analysisHelper.getMnem
                   (self.getRegVal(self.analysisHelper.getOperand(userData["currAddr"], 0))) == ""):
                    self.logger.debug("bad branch detected @%s" % self.hexString(userData["currAddr"]))
                    return True
        return False
    
    
    # recursively searches control flow graph dict returned by _explore for a  
    # single path from currentNode to target basic block, check path parameter upon return
    def _findPathFromGraph(self, path, graph, currentNode, target):
        if currentNode not in graph:
            return False
        for node in graph[currentNode]:
            if node in path:
                continue
            path.append(node)
            if node == target:
                return True
            if self._findPathFromGraph(path, graph, node, target):
                return True
            else:
                path.pop()
        return False
        
    # recursively searches control flow graph dict returned by _explore for 
    # up to maxPaths from currentNode to basic blocks in targets list, check paths parameter upon return
    def _findPathsFromGraph(self, paths, path, graph, currentNode, targets, maxPaths, searchedNodes, maxNodes):
        if searchedNodes == 0:
            self.searchedNodes = 0
        if currentNode not in graph:
            return
        if len(paths) >= maxPaths or self.searchedNodes >= maxNodes:
            return
        self.searchedNodes += 1
        for node in graph[currentNode]:
            if node in path:
                continue
            path.append(node)
            if node in targets:
                paths.append(deepcopy(path))
                path.pop()
                return
            self._findPathsFromGraph(paths, path, graph, node, targets, maxPaths, self.searchedNodes, maxNodes)
            path.pop()
        
    # returns a dictionary where the key is a node in the control flow graph 
    # and its value is a list of its successor nodes
    def _explore(self, start_bb, end_bb=None):
        stack = []
        discovered = []
        graph = {}
        stack.append(start_bb)
        while len(stack) > 0:
            bb = stack.pop()
            if bb.id not in discovered:
                discovered.append(bb.id)
                graph[bb.id] = []
                for block in bb.succs():
                    stack.append(block)
                    graph[bb.id].append(block.id)
                    if end_bb is not None and block.id == end_bb.id:
                        return graph
                    
        return graph

    def _regionInSegment(self, addr, size):
        segs = []
        for segVA in self.analysisHelper.getSegments():
            endVA = self.analysisHelper.getSegmentEnd(segVA)
            segs.append((segVA, endVA))

        for seg in segs:
            if ((seg[0] <= addr and seg[1] > addr) or # starts in segment
                (seg[0] <= addr + size and seg[1] > addr + size) or # ends in segment
                (seg[0] > addr and seg[1] < addr + size) # swallows segment
                ):
                return True

        return False

    def _regionOverlapsWithExistingRegion(self, addr, size):
        for region in self.uc.mem_regions():
            # if start or end of region falls in range of a previous region
            if ((addr >= region[0] and addr < region[1]) or
                    (addr + size >= region[0] and addr + size < region[1])):
                return True
            # if region completely envelopes a previous region
            if addr < region[0] and addr + size > region[1]:
                return True

        return False
    
    def _findUnusedMemRegion(self, size):
        candidate = 0x10000
        maxAddr = self.pageMask + 0x1000
        size = self.pageAlignUp(size)
        while candidate < maxAddr:
            if not self._regionOverlapsWithExistingRegion(candidate, size) and not self._regionInSegment(candidate, size):
                break

            candidate += 0x1000

        if candidate < maxAddr:
            return candidate

        self.logger.error("not enough memory for allocation!")
        return None
    
    def _cloneEmuMem(self, eh):
        self.resetEmulatorMemory()
        self.baseAddr = eh.baseAddr
        self.logger.debug("cloning provided emu memory")
        for region in eh.uc.mem_regions():
            size = region[1] - region[0] + 1
            self.logger.debug("mapping %s bytes @%s" %
                      (self.hexString(size), self.hexString(region[0])))
            self.uc.mem_map(region[0], size)
            self.logger.debug("copying region")
            self.writeEmuMem(region[0], eh.getEmuBytes(region[0], size))
        self._buildStack()
        

    # stack setup
    # stack pointer will begin in the middle of allocated stack size
    def _buildStack(self):
        self.stack = self.allocEmuMem(self.stackSize) + self.stackSize // 2 # fix for python3 
        self.writeEmuMem(self.stack - self.stackSize// 2, (b"\x00") * self.stackSize)

    def _enableVFP(self):
        if self.arch == unicorn.UC_ARCH_ARM:
            # for ARM, we must run this code in order to enable vector instructions in our emulator
            """
            mov.w r0, #0xf00000
            mcr p15, #0x0, r0, c1, c0, #0x2
            isb sy
            mov.w r3, #0x40000000
            vmsr fpexc, r3
            """
            # ENABLE_VFP_CODE = "\x0f\x06\xa0\xe3\x50\x0f\x01\xee\x6f\xf0\x7f\xf5\x01\x31\xa0\xe3\x10\x3a\xe8\xee"
            # self.emulateBytes(ENABLE_VFP_CODE, {}, [])
            tmp = self.uc.reg_read(unicorn.arm_const.UC_ARM_REG_C1_C0_2)
            self.uc.reg_write(unicorn.arm_const.UC_ARM_REG_C1_C0_2, tmp | (0xf << 20))
            self.uc.reg_write(unicorn.arm_const.UC_ARM_REG_FPEXC, 0x40000000)
        elif self.arch == unicorn.UC_ARCH_ARM64:
            """
            https://static.docs.arm.com/ddi0487/ca/DDI0487C_a_armv8_arm.pdf
            MRS X2, CPACR_EL1
            ORR X2, X2, #0x300000 # <-- set bits 20,21 to disable trapping for FP related instructions
            MSR  CPACR_EL1, X2
            NOP # <-- handle Unicorn bug
            """
            ENABLE_VFP_CODE = b"\x42\x10\x38\xd5\x42\x04\x6c\xb2\x42\x10\x18\xd5\x1f\x20\x03\xd5"
            self.emulateBytes(ENABLE_VFP_CODE)

    # prepare thread context
    def _prepEmuContext(self, registers=None, stack=None):
        mu = self.uc
        for reg in self.regs:
            mu.reg_write(self.regs[reg], 0)
        mu.reg_write(self.regs["sp"], self.stack)
        if registers:
            for reg in registers:
                val = registers[reg]
                if isinstance(val, str) or isinstance(val, bytes) or isinstance(val, bytearray):
                    if isinstance(val, str):
                        val = val.encode("latin1")
                        
                    mem = self.allocEmuMem(len(val))
                    self.writeEmuMem(mem, val)
                    val = mem
                elif isinstance(val, (int, long)):
                    pass
                else:
                    self.logger.error("incorrect type for %s" % reg)
                    return None
                mu.reg_write(self.regs[reg], val)
                registers[reg] = val

        # setup stack
        if stack:
            for i in range(0, len(stack)):
                if isinstance(stack[i], str) or isinstance(stack[i], bytes) or isinstance(stack[i], bytearray):
                    mem = self.allocEmuMem(len(stack[i]))
                    self.writeEmuMem(mem, stack[i])
                    stack[i] = mem
                    val = mem
                elif isinstance(stack[i], (int, long)):
                    val = stack[i]
                else:
                    self.logger.error("incorrect type for stack[%d]" % (i))
                    return None

                self.writeEmuMem(self.getRegVal("sp") + i *
                             self.size_pointer, struct.pack(self.pack_fmt, val))
