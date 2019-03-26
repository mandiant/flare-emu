<img src="resources/flare-emu_logo.jpg?raw=true " width="350"/>

# [flare-emu](#flare-emu)

**flare-emu** marries [IDA Pro](https://www.hex-rays.com/products/ida/)’s binary analysis capabilities with [Unicorn](https://www.unicorn-engine.org/)’s emulation framework to provide the user with an easy to use and flexible interface for scripting emulation tasks. It is designed to handle all the housekeeping of setting up a flexible and robust emulator for its supported architectures so that you can focus on solving your code analysis problems. Currently, **flare-emu** supports the `x86`, `x86_64`, `ARM`, and `ARM64` architectures.

It currently provides four different interfaces to serve your emulation needs, along with a slew of related helper and utility functions.

1.	`emulateRange` – This API is used to emulate a range of instructions, or a function, within a user-specified context. It provides options for user-defined hooks for both individual instructions and for when “call” instructions are encountered. The user can decide whether the emulator will skip over, or call into function calls. This interface provides an easy way for the user to specify values for given registers and stack arguments. If a bytestring is specified, it is written to the emulator’s memory and the pointer is written to the register or stack variable. After emulation, the user can make use of `flare-emu`’s utility functions to read data from the emulated memory or registers, or use the Unicorn emulation object that is returned for direct probing. A small wrapper function for `emulateRange`, named `emulateSelection`, can be used to emulate the range of instructions currently highlighted in IDA Pro. 

2. `iterate` - This API is used to force emulation down specific branches within a function in order to reach a given target. The user can specify a list of target addresses, or the address of a function from which a list of cross-references to the function is used as the targets, along with a callback for when a target is reached. The targets will be reached, regardless of conditions during emulation that may have caused different branches to be taken. Like the `emulateRange` API, options for user-defined hooks for both individual instructions and for when “call” instructions are encountered are provided. An example use of the iterate API is to achieve something similar to what our [argtracker](https://www.fireeye.com/blog/threat-research/2015/11/flare_ida_pro_script.html) tool does.

3. `iterateAllPaths` - This API is much like `iterate`, except that instead of providing a target address or addresses, you provide a target function that it will attempt to find all paths through and emulate. This is useful when you are performing code analysis that wants to reach every basic block of a function.

4. `emulateBytes` – This API provides a way to simply emulate a blob of extraneous shellcode. The provided bytes are not added to the IDB and are simply emulated as is. This can be useful for preparing the emulation environment. For example, `flare-emu` itself uses this API to manipulate a Model Specific Register (MSR) for the `ARM64` CPU that is not exposed by Unicorn in order to enable Vector Floating Point (VFP) instructions and register access. The Unicorn emulation object is returned for further probing by the user.

## [Installation](#installation)
To install `flare-emu`, simply drop it in your IDA Pro's `python` directory and import it as a module in your IDApython scripts. `flare-emu` depends on [Unicorn](https://www.unicorn-engine.org/) and its Python bindings.

**IMPORTANT NOTE**  
`flare-emu` was written using the new IDA Pro 7x API, it is not backwards compatible with previous versions of IDA Pro.

## [Usage](#usage)
While `flare-emu` can be used to solve many different code analysis problems, one of its more common uses is to aid in decrypting strings in malware binaries. [FLOSS](https://github.com/fireeye/flare-floss) is a great tool than can often do this automatically for you by attempting to identify the string decrypting function(s) and using emulation to decrypt the strings passed in at every cross-reference to it. However, it is not possible for FLOSS to always be able to identify these functions and emulate them properly using its generic approaches. Sometimes you have to do a little more work, and this is where `flare-emu` can save you a lot of time once you are comfortable with it. Let's walk through a common scenario a malware analyst encounters when dealing with encrypted strings.

### Easy String Decryption Scenario
You've identified the function to decrypt all the strings in an `x86_64` binary. This function is called all over the place and decrypts many different strings. In IDA Pro, you name this function `decryptString`. Here is your flare-emu script to decrypt all these strings and place comments with the decrypted strings at each function call as well as logging each decrypted string and the address it is decrypted at.

```
from __future__ import print_function
import idc
import idaapi
import idautils
import flare_emu

def decrypt(argv):
    myEH = flare_emu.EmuHelper()
    myEH.emulateRange(idc.get_name_ea_simple("decryptString"), registers = {"arg1":argv[0], "arg2":argv[1], 
                           "arg3":argv[2], "arg4":argv[3]})
    return myEH.getEmuString(argv[0])
    
def iterateCallback(eh, address, argv, userData):
    s = decrypt(argv)
    print("%016X: %s" % (address, s))
    idc.set_cmt(address, s, 0)
    
if __name__ == '__main__':   
    eh = flare_emu.EmuHelper()
    eh.iterate(idc.get_name_ea_simple("decryptString"), iterateCallback)
```

In `__main__`, we begin by creating an instance of the `EmuHelper` class from `flare-emu`. This is the class we use to do everything with `flare-emu`. Next, we use the `iterate` API, giving it the address of our `decryptString` function and the name of our callback function that `EmuHelper` will call for each cross-reference emulated up to. 

The `iterateCallback` function receives the EmuHelper instance, named `eh` here, along with the address of the cross-reference, the arguments passed to this particular call, and a special dictionary named `userData` here. `userData` is not used in this simple example, but think of it as a persistent context to your emulator where you can store your own custom data. Be careful though, because `flare-emu` itself also uses this dictionary to store critical information it needs to perform its tasks. One such piece of data is the `EmuHelper` instance itself, stored in the "EmuHelper" key. If you are interested, search the source code to learn more about this dictionary. This callback function simply calls the `decrypt` function, prints the decrypted string and creates a comment for it at the address of that call to `decryptString`.

`decrypt` creates a second instance of `EmuHelper` that is used to emulate the `decryptString` function itself, which will decrypt the string for us. The prototype of this `decryptString` function is as follows: `char * decryptString(char *text, int textLength, char *key, int keyLength)`. It simply decrypts the string in place. Our `decrypt` function passes in the arguments as received by the `iterateCallback` function to our call to `EmuHelper`'s `emulateRange` API. Since this is an `x86_64` binary, the calling convention uses registers to pass arguments and not the stack. `flare-emu` automatically determines which registers represent which arguments based on the architecture and file format of the binary as determined by IDA Pro, allowing you to write at least somewhat architecture agnostic code. If this were 32-bit `x86`, you would use the `stack` argument to pass the arguments instead, like so: `myEH.emulateRange(idc.get_name_ea_simple("decryptString"), stack = [0, argv[0], argv[1], argv[2], argv[3]])`. The first stack value is the return address in `x86`, so we just use `0` as a placeholder value here. Once emulation is complete, we call the `getEmuString` API to retrieve the null-terminated string stored in the memory location pointed to by the first argument passed to the function.

## [Emulation Functions](#emulationfuncs)
`emulateRange(startAddr, endAddr=None, registers=None, stack=None, instructionHook=None, callHook=None, memAccessHook=None, hookData=None, skipCalls=True, hookApis=True, count=0)` - Emulates the range of instructions starting at `startAddress` and ending at `endAddress`, not including the instruction at `endAddress`. If endAddress is `None`, emulation stops when a "return" type instruction is encountered within the same function that emulation began. 

* `registers` is a dictionary with keys being register names and values being register values. Some special register names are created by `flare-emu` and can be used here, such as `arg1`, `arg2`, etc., `ret`, and `pc`. 

* `stack` is an array of values to be pushed on the stack in reverse order, much like arguments to a function in `x86` are. In `x86`, remember to account for the first value in this array being used as the return address for a function call and not the first argument of the function. `flare-emu` will initialize the emulated thread's context and memory according to the values specified in the `registers` and `stack` arguments. If a string is specified for any of these values, it will be written to a location in memory and a pointer to that memory will be written to the specified register or stack location instead. 

* `instructionHook` can be a function you define to be called before each instruction is emulated. It has the following prototype: `instructionHook(unicornObject, address, instructionSize, userData)`.

* `callHook` can be a function you define to be called whenever a "call" type instruction is encountered during emulation. It has the following prototype: `callHook(address, arguments, functionName, userData)`.

* `hookData` is a dictionary containing user-defined data to be made available to your hook functions. It is a means to persist data throughout the emulation. `flare-emu` also uses this dictionary for its own purposes, so care must be taken not to define a key already defined. This variable is often named `userData` in user-defined hook functions due to its naming in Unicorn.

* `skipCalls` will cause the emulator to skip over "call" type instructions and adjust the stack accordingly, defaults to `True`.

* `hookApis` causes `flare-emu` to perform a naive implementation of some of the more common runtime and OS library functions it encounters during emulation. This frees you from having to be concerned about calls to functions such as `memcpy`, `strcat`, `malloc`, etc., and defaults to `True`.

* `memAccessHook` can be a function you define to be called whenever memory is accessed for reading or writing. It has the following prototype: `memAccessHook(unicornObject, accessType, memAccessAddress, memAccessSize, memValue, userData)`.

* `count` is the maximum number of instructions to emulate, defaults to `0` which means no limit.

`iterate(target, targetCallback, preEmuCallback=None, callHook=None, instructionHook=None, hookData=None, resetEmuMem=False, hookApis=True, memAccessHook=None)` - For each target specified by `target`, a separate emulation is performed from the beginning of the containing function up to the target address. Emulation will be forced down the branches necessary to reach each target. `target` can be the address of a function, in which case the target list is populated with all the cross-references to the specified function. Or, `target` can be an explicit list of targets.

* `targetCallback` is a function you create that will be called by `flare-emu` for each target that is reached during emulation. It has the following prototype: `instructionHook(emuHelper, address, arguments, userData)`.

* `preEmuCallback` is a function you create that will be called before emulation for each target begins. You can implement some setup code here if needed.

* `resetEmuMem` will cause `flare-emu` to reset the emulation memory before emulation of each target begins, defaults to `False`.

`iterateAllPaths(target, targetCallback, preEmuCallback=None, callHook=None, instructionHook=None, hookData=None, resetEmuMem=False, hookApis=True, memAccessHook=None, maxPaths=MAXCODEPATHS, maxNodes=MAXNODESEARCH)` - For the function containing the address `target`, a separate emulation is performed for each discovered path through it, up to `maxPaths`.

* `maxPaths` - the max number of paths through the function that will be searched for and emulated. Some of the more complex functions can cause the graph search function to take a very long time or never finish; tweak this parameter to meet your needs in a reasonable amount of time.

* `maxNodes` - the max number of basic blocks that will be searched when finding paths through the target function. This is a safety measure to prevent unreasonable search times and hangs and likely does not need to be changed.

`emulateBytes(bytes, registers=None, stack=None, baseAddress=0x400000, instructionHook=None, hookData=None)` - Writes the code contained in `bytes` to emulation memory at `baseAddress` if possible and emulates the instructions from the beginning to the end of `bytes`. 

## [Utility Functions](#utility)
The following is an incomplete list of some of the useful utility functions provided by the `EmuHelper` class.

* `hexString(value)` - Returns a hexadecimal formatted string for the value. Useful for logging and print statements.

* `getIDBString(address)` - Returns the string of characters located at an address in the IDB, up to a null terminator. Characters are not necessarily printable. Useful for retrieving strings without an emulation context.

* `skipInstruction(userData, useIDA=False)` - Call this from an emulation hook to skip the current instruction, moving the program counter to the next instruction. `useIDA` option was added to handle cases where IDA Pro folds multiple instructions into one pseudo instruction and you would like to skip all of them. This function cannot be called multiple times from a single instruction hook to skip multiple instructions. To skip multiple instructions, it is recommended not to write to the program counter directly if you are emulating ARM code as this might cause problems with thumb mode. Instead, try EmuHelper's `changeProgramCounter` API (described below).

* `changeProgramCounter(userData, newAddress)` - Call this from an emulation hook to change the value of the program counter register. This API takes care of thumb mode tracking for the ARM architecture.

* `getRegVal(registerName)` - Retrieves the value of the specified register, being sensitive to sub-register addressing. For example, "ax" will return the lower 16 bits of the EAX/RAX register in `x86`.

* `stopEmulation(userData)` - Call this from an emulation hook to stop emulation. Use this instead of calling the `emu_stop` Unicorn API so that the `EmuHelper` object can handle bookkeeping related to the `iterate` feature.

* `getEmuString(address)` -  Returns the string of characters located at an address in the emulated memory, up to a null terminator. Characters are not necessarily printable.

* `getEmuWideString(address)` -  Returns the string of "wide characters" located at an address in the emulated memory, up to a null terminator. "Wide characters" is meant loosely here to refer to any series of bytes containing a null byte every other byte, as would be the case for an ASCII string encoded in UTF-16 LE. Characters are not necessarily printable.

* `getEmuBytes(address, length)` - Returns a string of bytes located at an address in the emulated memory.

* `getEmuPtr(address)` - Returns the pointer value located at the given address.

* `writeEmuPtr(address)` - Writes the pointer value at the given address in the emulated memory.

* `loadBytes(bytes, address=None)` - Allocates memory in the emulator and writes the bytes to it.

* `isValidEmuPtr(address)` - Returns `True` if the provided address points to valid emulated memory.

* `getEmuMemRegion(address)` - Returns a tuple containing the start and end address of memory region containing the provided address, or `None` if the address is not valid.

* `getArgv()` - Call this from an emulation hook at a "call" type instruction to receive an array of the arguments to the function.

* `addApiHook(apiName, hook)` - Adds a new API hook for this instance of `EmuHelper`. Whenever a call instruction to `apiName` is encountered during emulation, `EmuHelper` will call the function specified by `hook`. If `hook` is a string, it is expected to be the name of an API already hooked by `EmuHelper`, in which case it will call its existing hook function. If `hook` is a function, it will call that function.


# [Learn More](#learn)
To learn more about **flare-emu**, please read our introductory blog at https://www.fireeye.com/blog/threat-research/2018/12/automating-objective-c-code-analysis-with-emulation.html.
