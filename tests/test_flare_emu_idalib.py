# Copyright 2025 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import os
import sys
from pathlib import Path

import pytest

# make flare_emu module avaible
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from unicorn import UC_ARCH_X86, UC_MEM_READ, UC_MEM_WRITE

import flare_emu

TEST_STRINGS = ["HELLO", "GOODBYE", "TEST"]

# using global variables to record results
test_iterateHooks = list()
test_chs = list()


CD = Path(__file__).resolve().parent


@pytest.fixture
def path(request) -> Path:
    return CD / request.param


def decode(argv):
    if len(sys.argv) == 3:
        myEH = flare_emu.EmuHelper(samplePath=sys.argv[1], isRizin=True)
    elif len(sys.argv) == 2:
        myEH = flare_emu.EmuHelper(samplePath=sys.argv[1])
    else:
        myEH = flare_emu.EmuHelper()
    print("testing emulateRange feature for _xorCrypt function")
    myEH.emulateRange(
        myEH.analysisHelper.getNameAddr("_xorCrypt"),
        registers={"arg1": argv[0], "arg2": argv[1], "arg3": argv[2], "arg4": argv[3]},
    )
    return myEH.getEmuString(argv[0]).decode("latin1")


def ch(address, argv, funcName, userData):
    global test_chs
    eh = userData["EmuHelper"]
    if funcName == "_xorCrypt":
        s = eh.getEmuString(argv[0])
        dec = decode(argv)
        if dec not in TEST_STRINGS:
            print("FAILED: incorrect decoded string @ %016X" % address)
            test_chs.append(False)
        else:
            print("emulateRange xorCrypt passed")
            test_chs.append(True)


def iterateHook(eh, address, argv, userData):
    global test_iterateHooks
    fmtStr = eh.getEmuString(argv[0]).decode("latin1")
    if fmtStr[0] != "%" or fmtStr[-1:] != "\n":
        print("FAILED: printf getting wrong arguments @ %016X" % address)
        test_iterateHooks.append(False)
    else:
        print("printf test passed")
        test_iterateHooks.append(True)


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


@pytest.mark.parametrize("path", ["flare_emu_test_x64", "flare_emu_test_arm64", "flare_emu_test_armv7"], indirect=True)
def test_iterate_printf(path: Path):
    try:
        import idapro

        sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
        import flare_emu_ida
    except ImportError as e:
        print(e)

    # idapro.enable_console_messages(True)
    idapro.open_database(str(path), run_auto_analysis=True)

    eh = flare_emu.EmuHelper()
    printfName = "_printf"

    print("testing iterate feature for printf function")
    ud = dict()
    eh.iterate(eh.analysisHelper.getNameAddr(printfName), iterateHook, callHook=ch, hookData=ud)

    idapro.close_database(save=False)

    assert all(test_iterateHooks)
    assert all(test_chs)


@pytest.mark.parametrize("path", ["flare_emu_test_x64"], indirect=True)
def test_memory_access_hook(path):
    """Compare memory access identified in IDA and hooked instructions."""

    try:
        import idapro

        sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
        import flare_emu_ida
    except ImportError as e:
        print(e)

    # idapro.enable_console_messages(True)
    idapro.open_database(str(path), run_auto_analysis=True)

    print("\ntesting memory access hook")

    eh = flare_emu.EmuHelper()
    main_va = eh.analysisHelper.getNameAddr("_main")
    userData = dict()
    userData["mov_types_hook"] = dict()
    eh.emulateRange(main_va, memAccessHook=get_mov_types_hook, hookData=userData)
    if get_mov_types(eh, main_va) != userData["mov_types_hook"]:
        print(
            "FAILED: memory access hook test. Memory access identified in binary analysis and hooked instructions differ."
        )
        assert False
    else:
        print("memory access hook test passed")
        assert True

    idapro.close_database()
