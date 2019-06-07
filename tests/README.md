# Testing

There are currently four IDAPython scripts used to test `flare-emu`.

* flare_emu_test.py - Basic tests of the `emulateRange` and `iterate` features
* flare_emu_test_hooks.py - Tests the naive implementations of all the supported CRT and Windows API hooks
* objc2_analyzer_test.py - Tests the basic functionality of objc2_analyzer.py
* flare_emu_test_discovery.py - Tests the `emulateFrom` feature with `strict` mode turned off to enable code discovery and fix anti-disassembly tricks present in the test binary

The `flare_emu_test_<arch>` binaries are Mach-O executables that should be loaded into IDA Pro and tested with the `flare_emu_test.py` IDAPython script.

The `flare_emu_winhooks_test_x86.exe` binary is a PE executable that should be loaded into IDA Pro and tested with the `flare_emu_test_hooks.py` IDAPython script. You may need to apply the `printf` name to the `printf` function in the binary if IDA Pro fails to do so.

The `objc2_analyzer_test_<arch>` binaries are Mach-O executables that should be loaded into IDA Pro and tested with the `objc2_analyzer_test.py` IDAPython script.

The `flare_emu_test_discovery` binary is a Mach-O executable that should be loaded into IDA Pro and tested with the `flare_emu_test_discovery.py` IDAPython script.

Check the printed output of these test scripts to ensure there are no reported errors.
