import flare_emu
import unicorn
import base64
import re
import binascii
import inspect
import logging

def _getLastError(eh, address, argv, funcName, userData):
    eh.uc.reg_write(eh.regs["ret"], eh.errorcode)
    
def _setLastError(eh, address, argv, funcName, userData):
    eh.errorcode = argv[0]

# return a fake handle value
def _returnHandleHook(eh, address, argv, funcName, userData):
    eh.uc.reg_write(eh.regs["ret"], 42)
    
def _returnParam1Hook(eh, address, argv, funcName, userData):
    eh.uc.reg_write(eh.regs["ret"], argv[0])

def _allocMem1Hook(eh, address, argv, funcName, userData):
    allocSize = argv[0]
    allocSize = eh._checkMemSize(allocSize, userData)
    eh.uc.reg_write(eh.regs["ret"], eh.allocEmuMem(allocSize))
    
def _allocMem2Hook(eh, address, argv, funcName, userData):
    allocSize = argv[1]
    allocSize = eh._checkMemSize(allocSize, userData)
    eh.uc.reg_write(eh.regs["ret"], eh.allocEmuMem(allocSize))
    
def _allocMem3Hook(eh, address, argv, funcName, userData):
    allocSize = argv[2]
    allocSize = eh._checkMemSize(allocSize, userData)
    eh.uc.reg_write(eh.regs["ret"], eh.allocEmuMem(allocSize))
    
def _callocHook(eh, address, argv, funcName, userData):
    allocSize = argv[0] * argv[1]
    allocSize = eh._checkMemSize(allocSize, userData)
    eh.uc.reg_write(eh.regs["ret"], eh.allocEmuMem(allocSize))
    
# deny "in place only" flag
def _heapReAllocHook(eh, address, argv, funcName, userData):
    HEAP_REALLOC_IN_PLACE_ONLY = 0x10
    if argv[1] & HEAP_REALLOC_IN_PLACE_ONLY:
        eh.uc.reg_write(eh.regs["ret"], 0)
    else:
        allocSize = argv[3]
        allocSize = eh._checkMemSize(allocSize, userData)
        region = eh.getEmuMemRegion(argv[2])
        if region is not None:
            allocSize = max(region[1] - region[0], allocSize)
            memAddr = eh.allocEmuMem(allocSize)
            eh.copyEmuMem(memAddr, region[0], region[1] - region[0], userData)
        else:
            memAddr = eh.allocEmuMem(allocSize)
        eh.uc.reg_write(eh.regs["ret"], memAddr)
    
        
def _reallocHook(eh, address, argv, funcName, userData):
    allocSize = argv[1]
    allocSize = eh._checkMemSize(allocSize, userData)
    region = eh.getEmuMemRegion(argv[0])
    if region is not None:
        allocSize = max(region[1] - region[0], allocSize)
        memAddr = eh.allocEmuMem(allocSize)
        eh.copyEmuMem(memAddr, region[0], region[1] - region[0], userData)
    else:
        memAddr = eh.allocEmuMem(allocSize)
    eh.uc.reg_write(eh.regs["ret"], memAddr)
        
# allocate regardless of commit flag, keep a mapping of requested addr -> actual addr
def _virtualAllocHook(eh, address, argv, funcName, userData):
    allocAddr = argv[0]
    if allocAddr in eh.allocMap:
        eh.uc.reg_write(eh.regs["ret"], eh.allocMap[allocAddr][0])
        return
    allocSize = argv[1]
    allocSize = eh._checkMemSize(allocSize, userData)  
    memAddr = eh.allocEmuMem(allocSize, allocAddr)
    eh.allocMap[allocAddr] = (memAddr, allocSize)
    eh.uc.reg_write(eh.regs["ret"], memAddr)
    
# handle same as VirtualAlloc hook, just with different argument placement
def _virtualAllocExHook(eh, address, argv, funcName, userData):
    allocAddr = argv[1]
    if allocAddr in eh.allocMap:
        eh.uc.reg_write(eh.regs["ret"], eh.allocMap[allocAddr][0])
        return
    allocSize = argv[2]
    allocSize = eh._checkMemSize(allocSize, userData)  
    memAddr = eh.allocEmuMem(allocSize, allocAddr)
    eh.allocMap[allocAddr] = (memAddr, allocSize)
    eh.uc.reg_write(eh.regs["ret"], memAddr)
    
def _memcpyHook(eh, address, argv, funcName, userData):
    copySize = argv[2]
    copySize = eh._checkMemSize(copySize, userData)
    srcRegion = eh.getEmuMemRegion(argv[1])
    dstRegion = eh.getEmuMemRegion(argv[0])
    if dstRegion is None:
        logging.debug("dest memory does not exist for memcpy @%s" % eh.hexString(address))
        dstRegion = eh.getEmuMemRegion(eh.allocEmuMem(copySize))
        argv[0] = dstRegion[0]
    if srcRegion is None:
        logging.debug("source memory does not exist for memcpy @%s" % eh.hexString(address))
    else:
        if copySize <= srcRegion[1] - argv[1] and copySize <= dstRegion[1] - argv[0]:
            eh.copyEmuMem(argv[0], argv[1], copySize, userData)
        else:
            logging.debug("dest memory not large enough @%s" % eh.hexString(address))
    eh.uc.reg_write(eh.regs["ret"], argv[0])
    
def _strlenHook(eh, address, argv, funcName, userData):
    if eh.isValidEmuPtr(argv[0]):
        eh.uc.reg_write(eh.regs["ret"], len(eh.getEmuString(argv[0])))
    else:
        eh.uc.reg_write(eh.regs["ret"], 0)
        
def _wcslenHook(eh, address, argv, funcName, userData):
    if eh.isValidEmuPtr(argv[0]):
        eh.uc.reg_write(eh.regs["ret"], len(eh.getEmuWideString(argv[0]).decode("utf-16")))
    else:
        eh.uc.reg_write(eh.regs["ret"], 0)

def _strnlenHook(eh, address, argv, funcName, userData):
    strnlen = eh._checkMemSize(argv[1], userData)
    if eh.isValidEmuPtr(argv[0]):
        strlen = len(eh.getEmuString(argv[0]))
        strlen = min(strlen, strnlen)
        eh.uc.reg_write(eh.regs["ret"], strlen)
    else:
        eh.uc.reg_write(eh.regs["ret"], 0)
        
def _wcsnlenHook(eh, address, argv, funcName, userData):
    strnlen = eh._checkMemSize(argv[1], userData)
    if eh.isValidEmuPtr(argv[0]):
        strlen = len(eh.getEmuWideString(argv[0]).decode("utf-16"))
        if strlen > strnlen:
            strlen = argv[1]
        eh.uc.reg_write(eh.regs["ret"], strnlen)
    else:
        eh.uc.reg_write(eh.regs["ret"], 0)

def _strcmpHook(eh, address, argv, funcName, userData):
    if eh.isValidEmuPtr(argv[0]) and eh.isValidEmuPtr(argv[1]):
        str1 = eh.getEmuString(argv[1])
        str2 = eh.getEmuString(argv[0])
        if str1 == str2:
            eh.uc.reg_write(eh.regs["ret"], 0)
            return
    if eh.size_pointer == 8:
        val = 0xffffffffffffffff
    else:
        val = 0xffffffff
    eh.uc.reg_write(eh.regs["ret"], val)
    
def _strncmpHook(eh, address, argv, funcName, userData):
    strnlen = eh._checkMemSize(argv[2], userData)
    if eh.isValidEmuPtr(argv[0]) and eh.isValidEmuPtr(argv[1]):
        str1 = eh.getEmuString(argv[1])
        str2 = eh.getEmuString(argv[0])
        if str1[:strnlen] == str2[:strnlen]:
            eh.uc.reg_write(eh.regs["ret"], 0)
            return
    if eh.size_pointer == 8:
        val = 0xffffffffffffffff
    else:
        val = 0xffffffff
    eh.uc.reg_write(eh.regs["ret"], val)
    
def _stricmpHook(eh, address, argv, funcName, userData):
    if eh.isValidEmuPtr(argv[0]) and eh.isValidEmuPtr(argv[1]):
        str1 = eh.getEmuString(argv[1])
        str2 = eh.getEmuString(argv[0])
        if str1.lower() == str2.lower():
            eh.uc.reg_write(eh.regs["ret"], 0)
            return
    if eh.size_pointer == 8:
        val = 0xffffffffffffffff
    else:
        val = 0xffffffff
    eh.uc.reg_write(eh.regs["ret"], val)
    
def _strnicmpHook(eh, address, argv, funcName, userData):
    strnlen = eh._checkMemSize(argv[2], userData)
    if eh.isValidEmuPtr(argv[0]) and eh.isValidEmuPtr(argv[1]):
        str1 = eh.getEmuString(argv[1])
        str2 = eh.getEmuString(argv[0])
        if str1[:strnlen].lower() == str2[:strnlen].lower():
            eh.uc.reg_write(eh.regs["ret"], 0)
            return
    if eh.size_pointer == 8:
        val = 0xffffffffffffffff
    else:
        val = 0xffffffff
    eh.uc.reg_write(eh.regs["ret"], val)
    
def _wcscmpHook(eh, address, argv, funcName, userData):
    if eh.isValidEmuPtr(argv[0]) and eh.isValidEmuPtr(argv[1]):
        str1 = eh.getEmuWideString(argv[1]).decode("utf-16")
        str2 = eh.getEmuWideString(argv[0]).decode("utf-16")
        if str1 == str2:
            eh.uc.reg_write(eh.regs["ret"], 0)
            return
    if eh.size_pointer == 8:
        val = 0xffffffffffffffff
    else:
        val = 0xffffffff
    eh.uc.reg_write(eh.regs["ret"], val)
    
def _wcsncmpHook(eh, address, argv, funcName, userData):
    strnlen = eh._checkMemSize(argv[2], userData)
    if eh.isValidEmuPtr(argv[0]) and eh.isValidEmuPtr(argv[1]):
        str1 = eh.getEmuWideString(argv[1]).decode("utf-16")
        str2 = eh.getEmuWideString(argv[0]).decode("utf-16")
        if str1[:strnlen] == str2[:strnlen]:
            eh.uc.reg_write(eh.regs["ret"], 0)
            return
    if eh.size_pointer == 8:
        val = 0xffffffffffffffff
    else:
        val = 0xffffffff
    eh.uc.reg_write(eh.regs["ret"], val)
    
def _wcsicmpHook(eh, address, argv, funcName, userData):
    if eh.isValidEmuPtr(argv[0]) and eh.isValidEmuPtr(argv[1]):
        str1 = eh.getEmuWideString(argv[1]).decode("utf-16")
        str2 = eh.getEmuWideString(argv[0]).decode("utf-16")
        if str1.lower() == str2.lower():
            eh.uc.reg_write(eh.regs["ret"], 0)
            return
    if eh.size_pointer == 8:
        val = 0xffffffffffffffff
    else:
        val = 0xffffffff
    eh.uc.reg_write(eh.regs["ret"], val)
    
def _wcsnicmpHook(eh, address, argv, funcName, userData):
    strnlen = eh._checkMemSize(argv[2], userData)
    if eh.isValidEmuPtr(argv[0]) and eh.isValidEmuPtr(argv[1]):
        str1 = eh.getEmuWideString(argv[1]).decode("utf-16")
        str2 = eh.getEmuWideString(argv[0]).decode("utf-16")
        if str1[:strnlen].lower() == str2[:strnlen].lower():
            eh.uc.reg_write(eh.regs["ret"], 0)
            return
    if eh.size_pointer == 8:
        val = 0xffffffffffffffff
    else:
        val = 0xffffffff
    eh.uc.reg_write(eh.regs["ret"], val)
    
def _strcpyHook(eh, address, argv, funcName, userData):
    if eh.isValidEmuPtr(argv[1]):
        src = eh.getEmuString(argv[1]) + "\x00"
        dstRegion = eh.getEmuMemRegion(argv[0])
        if dstRegion is None:
            logging.debug("dest memory does not exist for strcpy @%s" % eh.hexString(address))
            dstRegion = eh.getEmuMemRegion(eh.allocEmuMem(len(src)))
            argv[0] = dstRegion[0]
        if len(src) <= dstRegion[1] - argv[0]:
            eh.uc.mem_write(argv[0], src)
            eh.uc.reg_write(eh.regs["ret"], argv[0])
            return
        else:
            logging.debug("dest memory not large enough @%s" % eh.hexString(address))

    if eh.size_pointer == 8:
        val = 0xffffffffffffffff
    else:
        val = 0xffffffff
    eh.uc.reg_write(eh.regs["ret"], val)
    
def _strncpyHook(eh, address, argv, funcName, userData):
    if eh.isValidEmuPtr(argv[1]):
        strnlen = eh._checkMemSize(argv[2], userData)
        src = eh.getEmuString(argv[1])
        dstRegion = eh.getEmuMemRegion(argv[0])
        if dstRegion is None:
            logging.debug("dest memory does not exist for strncpy @%s" % eh.hexString(address))
            dstRegion = eh.getEmuMemRegion(eh.allocEmuMem(strnlen))
            argv[0] = dstRegion[0]
        if strnlen <= dstRegion[1] - argv[0]:
            if strnlen > len(src):
                src = src.ljust(strnlen, "\x00")
            eh.uc.mem_write(argv[0], src)
            eh.uc.reg_write(eh.regs["ret"], argv[0])
            return
        else:
            logging.debug("dest memory not large enough @%s" % eh.hexString(address))

    if eh.size_pointer == 8:
        val = 0xffffffffffffffff
    else:
        val = 0xffffffff
    eh.uc.reg_write(eh.regs["ret"], val)
    
def _strncpysHook(eh, address, argv, funcName, userData):
    if eh.isValidEmuPtr(argv[2]):
        strnlen = eh._checkMemSize(argv[3], userData)
        src = eh.getEmuString(argv[2])
        dstRegion = eh.getEmuMemRegion(argv[0])
        if dstRegion is None:
            logging.debug("dest memory does not exist for strncpy_s @%s" % eh.hexString(address))
            dstRegion = eh.getEmuMemRegion(eh.allocEmuMem(strnlen))
            argv[0] = dstRegion[0]
        
        strnlen = min(strnlen, len(src))
        if strnlen + 1 <= dstRegion[1] - argv[0]:
            eh.uc.mem_write(argv[0], src + "\x00")
            eh.uc.reg_write(eh.regs["ret"], 0)
            return
        else:
            logging.debug("dest memory not large enough @%s" % eh.hexString(address))

    if eh.size_pointer == 8:
        val = 0xffffffffffffffff
    else:
        val = 0xffffffff
    eh.uc.reg_write(eh.regs["ret"], val)
   
def _wcscpyHook(eh, address, argv, funcName, userData):
    if eh.isValidEmuPtr(argv[1]):
        src = eh.getEmuWideString(argv[1]) + "\x00\x00"
        dstRegion = eh.getEmuMemRegion(argv[0])
        if dstRegion is None:
            logging.debug("dest memory does not exist for wcscpy @%s" % eh.hexString(address))
            dstRegion = eh.getEmuMemRegion(eh.allocEmuMem(len(src)))
            argv[0] = dstRegion[0]
        if len(src) <= dstRegion[1] - argv[0]:
            eh.uc.mem_write(argv[0], src)
            eh.uc.reg_write(eh.regs["ret"], argv[0])
            return
        else:
            logging.debug("dest memory not large enough @%s" % eh.hexString(address))

    if eh.size_pointer == 8:
        val = 0xffffffffffffffff
    else:
        val = 0xffffffff
    eh.uc.reg_write(eh.regs["ret"], val)
    
def _wcsncpyHook(eh, address, argv, funcName, userData):
    if eh.isValidEmuPtr(argv[1]):
        strnlen = eh._checkMemSize(argv[2] * 2, userData)
        src = eh.getEmuWideString(argv[1])
        dstRegion = eh.getEmuMemRegion(argv[0])
        if dstRegion is None:
            logging.debug("dest memory does not exist for wcsncpy @%s" % eh.hexString(address))
            dstRegion = eh.getEmuMemRegion(eh.allocEmuMem(strnlen))
            argv[0] = dstRegion[0]
        if strnlen <= dstRegion[1] - argv[0]:
            if strnlen > len(src):
                src = src.ljust(strnlen, "\x00")
            eh.uc.mem_write(argv[0], src)
            eh.uc.reg_write(eh.regs["ret"], argv[0])
            return
        else:
            logging.debug("dest memory not large enough @%s" % eh.hexString(address))

    if eh.size_pointer == 8:
        val = 0xffffffffffffffff
    else:
        val = 0xffffffff
    eh.uc.reg_write(eh.regs["ret"], val)
    
def _wcsncpysHook(eh, address, argv, funcName, userData):
    if eh.isValidEmuPtr(argv[2]):
        strnlen = eh._checkMemSize(argv[3] * 2, userData)
        src = eh.getEmuWideString(argv[2])
        dstRegion = eh.getEmuMemRegion(argv[0])
        if dstRegion is None:
            logging.debug("dest memory does not exist for wcsncpy_s @%s" % eh.hexString(address))
            dstRegion = eh.getEmuMemRegion(eh.allocEmuMem(strnlen))
            argv[0] = dstRegion[0]
            
        strnlen = min(strnlen, len(src))
        if strnlen + 2 <= dstRegion[1] - argv[0]:
            eh.uc.mem_write(argv[0], src[:strnlen] + "\x00\x00")
            eh.uc.reg_write(eh.regs["ret"], 0)
            return
        else:
            logging.debug("dest memory not large enough @%s" % eh.hexString(address))

    if eh.size_pointer == 8:
        val = 0xffffffffffffffff
    else:
        val = 0xffffffff
    eh.uc.reg_write(eh.regs["ret"], val)

def _memchrHook(eh, address, argv, funcName, userData):
    dstRegion = eh.getEmuMemRegion(argv[0])
    if dstRegion is not None:
        srch = chr(argv[1] & 0xFF)
        srchlen = argv[2]
        # truncate search to end of region
        if argv[0] + srchlen > dstRegion[1]:
            srchlen = dstRegion[1] - argv[0]
        buf = str(eh.uc.mem_read(argv[0], srchlen))
        offs = buf.find(srch)
        if offs > -1:
            eh.uc.reg_write(eh.regs["ret"], argv[0] + offs)
            return
            
    eh.uc.reg_write(eh.regs["ret"], 0)
    
def _mbstowcsHook(eh, address, argv, funcName, userData):
    if eh.isValidEmuPtr(argv[1]):
        bufSize = eh._checkMemSize(argv[2] * 2, userData)
        src = eh.getEmuString(argv[1])
        dstRegion = eh.getEmuMemRegion(argv[0])
        if dstRegion is None:
            logging.debug("dest memory does not exist for mbtowc variant @%s" % eh.hexString(address))
            dstRegion = eh.getEmuMemRegion(eh.allocEmuMem(bufSize))
            argv[0] = dstRegion[0]

        if argv[2] > len(src):
            src = src.ljust(argv[2], "\x00")
        else:
            src += "\x00"
        if len(src.encode("utf-16")[2:]) <= dstRegion[1] - argv[0]:
            eh.uc.mem_write(argv[0], src.encode("utf-16")[2:])
            eh.uc.reg_write(eh.regs["ret"], len(src))
            return
        else:
            logging.debug("dest memory not large enough @%s" % eh.hexString(address))

    eh.uc.reg_write(eh.regs["ret"], 0)
    
def _mbtowcHook(eh, address, argv, funcName, userData):
    if eh.isValidEmuPtr(argv[1]):
        src = eh.getEmuString(argv[1])[0]
        dstRegion = eh.getEmuMemRegion(argv[0])
        if dstRegion is None:
            logging.debug("dest memory does not exist for mbtowc variant @%s" % eh.hexString(address))
            dstRegion = eh.getEmuMemRegion(eh.allocEmuMem(0x1000))
            argv[0] = dstRegion[0]
        eh.uc.mem_write(argv[0], src.encode("utf-16")[2:4] + "\x00\x00")
        eh.uc.reg_write(eh.regs["ret"], 1)
        return

    eh.uc.reg_write(eh.regs["ret"], 0)
    
def _mbstowcsHook(eh, address, argv, funcName, userData):
    if eh.isValidEmuPtr(argv[1]):
        maxBufSize = eh._checkMemSize(argv[2] * 2, userData)
        src = eh.getEmuString(argv[1])
        if len(src) < argv[2]:
            src += "\x00"
        else:
            src = src[:argv[2]]
        dstRegion = eh.getEmuMemRegion(argv[0])
        if dstRegion is None:
            logging.debug("dest memory does not exist for mbtowc variant @%s" % eh.hexString(address))
            dstRegion = eh.getEmuMemRegion(eh.allocEmuMem(maxBufSize))
            argv[0] = dstRegion[0]
        if len(src) * 2 + 2 <= dstRegion[1] - argv[0]:
            eh.uc.mem_write(argv[0], src.encode("utf-16")[2:] + "\x00\x00")
            eh.uc.reg_write(eh.regs["ret"], len(src.replace("\x00", "")))
            return
        else:
            logging.debug("dest memory not large enough @%s" % eh.hexString(address))

    eh.uc.reg_write(eh.regs["ret"], 0)
    
def _wctombHook(eh, address, argv, funcName, userData):
    if eh.isValidEmuPtr(argv[1]):
        src = eh.getEmuWideString(argv[1]).decode("utf-16")
        dstRegion = eh.getEmuMemRegion(argv[0])
        if dstRegion is None:
            logging.debug("dest memory does not exist for wctomb variant @%s" % eh.hexString(address))
            dstRegion = eh.getEmuMemRegion(eh.allocEmuMem(0x1000))
        argv[0] = dstRegion[0]
        eh.uc.mem_write(argv[0], src[0])
        eh.uc.reg_write(eh.regs["ret"], 1)
        return

    eh.uc.reg_write(eh.regs["ret"], 0)
    
def _wcstombsHook(eh, address, argv, funcName, userData):
    if eh.isValidEmuPtr(argv[1]):
        bufSize = eh._checkMemSize(argv[2], userData)
        src = eh.getEmuWideString(argv[1]).decode("utf-16")
        if len(src) < argv[2]:
            src += "\x00"
        else:
            src = src[:argv[2]]
        dstRegion = eh.getEmuMemRegion(argv[0])
        if dstRegion is None:
            logging.debug("dest memory does not exist for wctomb variant @%s" % eh.hexString(address))
            dstRegion = eh.getEmuMemRegion(eh.allocEmuMem(bufSize))
            argv[0] = dstRegion[0]
        if bufSize + 1 <= dstRegion[1] - argv[0]:
            if bufSize > len(src):
                src = src.ljust(bufSize, "\x00")
            eh.uc.mem_write(argv[0], src + "\x00")
            eh.uc.reg_write(eh.regs["ret"], len(src.replace("\x00", "")))
            return
        else:
            logging.debug("dest memory not large enough @%s" % eh.hexString(address))

    eh.uc.reg_write(eh.regs["ret"], 0)
    
def _multiByteToWideCharHook(eh, address, argv, funcName, userData):
    if eh.isValidEmuPtr(argv[2]):
        src = eh.getEmuString(argv[2])
        srcLen = eh.getSignedValue(argv[3])
        if srcLen == -1:
            src += "\x00"
            maxBufSize = eh._checkMemSize(len(src) * 2, userData)
        else:
            maxBufSize = eh._checkMemSize(srcLen * 2, userData)
        
        if len(src) < srcLen:
            src += "\x00"
        elif srcLen != -1:
            src = src[:srcLen]
            
        if argv[5] == 0:
            eh.uc.reg_write(eh.regs["ret"], len(src) * 2)
            return
        dstRegion = eh.getEmuMemRegion(argv[4])
        if dstRegion is None:
            logging.debug("dest memory does not exist for mbtowc variant @%s" % eh.hexString(address))
            dstRegion = eh.getEmuMemRegion(eh.allocEmuMem(maxBufSize))
            argv[4] = dstRegion[0]
        if len(src) * 2 + 2 <= dstRegion[1] - argv[4]:
            eh.uc.mem_write(argv[4], src.encode("utf-16")[2:] + "\x00\x00")
            eh.uc.reg_write(eh.regs["ret"], len(src))
            return
        else:
            logging.debug("dest memory not large enough @%s" % eh.hexString(address))

    eh.uc.reg_write(eh.regs["ret"], 0)
    
def _wideCharToMultiByteHook(eh, address, argv, funcName, userData):
    if eh.isValidEmuPtr(argv[2]):
        src = eh.getEmuWideString(argv[2]).decode("utf-16")
        srcLen = eh.getSignedValue(argv[3])
        if srcLen == -1:
            src += "\x00"
            maxBufSize = eh._checkMemSize(len(src), userData)
        else:
            maxBufSize = eh._checkMemSize(srcLen, userData)
        
        if len(src) < srcLen:
            src += "\x00"
        elif srcLen != -1:
            src = src[:srcLen]
            
        if argv[5] == 0:
            eh.uc.reg_write(eh.regs["ret"], len(src))
            return
        dstRegion = eh.getEmuMemRegion(argv[4])
        if dstRegion is None:
            logging.debug("dest memory does not exist for mbtowc variant @%s" % eh.hexString(address))
            dstRegion = eh.getEmuMemRegion(eh.allocEmuMem(maxBufSize))
            argv[4] = dstRegion[0]
        if len(src) + 1 <= dstRegion[1] - argv[4]:
            eh.uc.mem_write(argv[4], src + "\x00")
            eh.uc.reg_write(eh.regs["ret"], len(src))
            return
        else:
            logging.debug("dest memory not large enough @%s" % eh.hexString(address))

    eh.uc.reg_write(eh.regs["ret"], 0)
    
def _memsetHook(eh, address, argv, funcName, userData):
    setSize = argv[2]
    setSize = eh._checkMemSize(setSize, userData)
    dstRegion = eh.getEmuMemRegion(argv[0])
    src = chr(argv[1] & 0xFF)
    if dstRegion is None:
        logging.debug("dest memory does not exist for memset @%s" % eh.hexString(address))
        dstRegion = eh.getEmuMemRegion(eh.allocEmuMem(setSize))
        argv[0] = dstRegion[0]
    if setSize <= dstRegion[1] - argv[0]:
        eh.uc.mem_write(argv[0], src * setSize)
    else:
        logging.debug("dest memory not large enough @%s" % eh.hexString(address))
    eh.uc.reg_write(eh.regs["ret"], argv[0])

def _bzeroHook(eh, address, argv, funcName, userData):
    setSize = argv[1]
    setSize = eh._checkMemSize(setSize, userData)
    dstRegion = eh.getEmuMemRegion(argv[0])
    src = "\x00"
    if dstRegion is None:
        logging.debug("dest memory does not exist for memset @%s" % eh.hexString(address))
        dstRegion = eh.getEmuMemRegion(eh.allocEmuMem(setSize))
        argv[0] = dstRegion[0]
    if setSize <= dstRegion[1] - argv[0]:
        eh.uc.mem_write(argv[0], src * setSize)
    else:
        logging.debug("dest memory not large enough @%s" % eh.hexString(address))
    eh.uc.reg_write(eh.regs["ret"], argv[0])
    
def _strcatHook(eh, address, argv, funcName, userData):
    if eh.isValidEmuPtr(argv[1]):
        src = eh.getEmuString(argv[1]) + "\x00"
        dstRegion = eh.getEmuMemRegion(argv[0])
        if dstRegion is None:
            logging.debug("dest memory does not exist for strcat @%s" % eh.hexString(address))
            dstRegion = eh.getEmuMemRegion(eh.allocEmuMem(len(src) + 1))
            argv[0] = dstRegion[0]
        dst = eh.getEmuString(argv[0])
        if len(dst) + len(src) <= dstRegion[1] - argv[0]:
            eh.uc.mem_write(argv[0], dst + src)
            eh.uc.reg_write(eh.regs["ret"], argv[0])
            return

    eh.uc.reg_write(eh.regs["ret"], 0)
                
def _strncatHook(eh, address, argv, funcName, userData):
    if eh.isValidEmuPtr(argv[1]):
        strnlen = eh._checkMemSize(argv[2], userData)
        src = eh.getEmuString(argv[1])
        strnlen = min(strnlen, len(src))
        dstRegion = eh.getEmuMemRegion(argv[0])
        if dstRegion is None:
            logging.debug("dest memory does not exist for strncat @%s" % eh.hexString(address))
            dstRegion = eh.getEmuMemRegion(eh.allocEmuMem(strnlen + 1))
            argv[0] = dstRegion[0]
        dst = eh.getEmuString(argv[0])
        if len(dst) + strnlen + 1 <= dstRegion[1] - argv[0]:
            eh.uc.mem_write(argv[0], dst + src[:strnlen] + "\x00")
            eh.uc.reg_write(eh.regs["ret"], argv[0])
            return

    eh.uc.reg_write(eh.regs["ret"], 0)

def _wcscatHook(eh, address, argv, funcName, userData):
    if eh.isValidEmuPtr(argv[1]):
        src = eh.getEmuWideString(argv[1]) + "\x00\x00"
        dstRegion = eh.getEmuMemRegion(argv[0])
        if dstRegion is None:
            logging.debug("dest memory does not exist for wcscat @%s" % eh.hexString(address))
            dstRegion = eh.getEmuMemRegion(eh.allocEmuMem(len(src)))
            argv[0] = dstRegion[0]
        dst = eh.getEmuWideString(argv[0])
        if len(dst) + len(src) <= dstRegion[1] - argv[0]:
            eh.uc.mem_write(argv[0], dst + src)
            eh.uc.reg_write(eh.regs["ret"], argv[0])
            return

    eh.uc.reg_write(eh.regs["ret"], 0)

def _wcsncatHook(eh, address, argv, funcName, userData):
    if eh.isValidEmuPtr(argv[1]):
        strnlen = eh._checkMemSize(argv[2], userData)
        src = eh.getEmuWideString(argv[1])
        strnlen = min(strnlen * 2, len(src))
        dstRegion = eh.getEmuMemRegion(argv[0])
        if dstRegion is None:
            logging.debug("dest memory does not exist for wcsncat @%s" % eh.hexString(address))
            dstRegion = eh.getEmuMemRegion(eh.allocEmuMem(strnlen + 2))
            argv[0] = dstRegion[0]
        dst = eh.getEmuWideString(argv[0])
        if len(dst) + strnlen + 2 <= dstRegion[1] - argv[0]:
            eh.uc.mem_write(argv[0], dst + src[:strnlen] + "\x00\x00")
            eh.uc.reg_write(eh.regs["ret"], argv[0])
            return

    eh.uc.reg_write(eh.regs["ret"], 0)
    
def _strchrHook(eh, address, argv, funcName, userData):
    if eh.isValidEmuPtr(argv[0]):
        s = eh.getEmuString(argv[0])
        idx = s.find(chr(argv[1] & 0xFF))
        if idx != -1:
            eh.uc.reg_write(eh.regs["ret"], argv[0] + idx)
            return

    eh.uc.reg_write(eh.regs["ret"], 0)

def _wcschrHook(eh, address, argv, funcName, userData):
    if eh.isValidEmuPtr(argv[0]):
        s = eh.getEmuWideString(argv[0]).decode("utf-16")
        idx = s.find(chr(argv[1] & 0xFF))
        if idx != -1:
            eh.uc.reg_write(eh.regs["ret"], argv[0] + idx * 2)
            return

    eh.uc.reg_write(eh.regs["ret"], 0)

def _strrchrHook(eh, address, argv, funcName, userData):
    if eh.isValidEmuPtr(argv[0]):
        s = eh.getEmuString(argv[0])
        idx = s.rfind(chr(argv[1] & 0xFF))
        if idx != -1:
            eh.uc.reg_write(eh.regs["ret"], argv[0] + idx)
            return
    
    eh.uc.reg_write(eh.regs["ret"], 0)
        
def _wcsrchrHook(eh, address, argv, funcName, userData):
    if eh.isValidEmuPtr(argv[0]):
        s = eh.getEmuWideString(argv[0]).decode("utf-16")
        idx = s.rfind(chr(argv[1] & 0xFF))
        if idx != -1:
            eh.uc.reg_write(eh.regs["ret"], argv[0] + idx * 2)
            return

    eh.uc.reg_write(eh.regs["ret"], 0)
    
def _strlwrHook(eh, address, argv, funcName, userData):
    if eh.isValidEmuPtr(argv[0]):
        s = eh.getEmuString(argv[0])
        eh.uc.mem_write(argv[0], s.lower())
        eh.uc.reg_write(eh.regs["ret"], argv[0])
        return
    
    eh.uc.reg_write(eh.regs["ret"], 0)
    
def _struprHook(eh, address, argv, funcName, userData):
    if eh.isValidEmuPtr(argv[0]):
        s = eh.getEmuString(argv[0])
        eh.uc.mem_write(argv[0], s.upper())
        eh.uc.reg_write(eh.regs["ret"], argv[0])
        return
    
    eh.uc.reg_write(eh.regs["ret"], 0)
    
def _wcslwrHook(eh, address, argv, funcName, userData):
    if eh.isValidEmuPtr(argv[0]):
        s = eh.getEmuWideString(argv[0]).decode("utf-16")
        eh.uc.mem_write(argv[0], s.lower().encode("utf-16")[2:])
        eh.uc.reg_write(eh.regs["ret"], argv[0])
        return
    
    eh.uc.reg_write(eh.regs["ret"], 0)
    
def _wcsuprHook(eh, address, argv, funcName, userData):
    if eh.isValidEmuPtr(argv[0]):
        s = eh.getEmuWideString(argv[0]).decode("utf-16")
        eh.uc.mem_write(argv[0], s.upper().encode("utf-16")[2:])
        eh.uc.reg_write(eh.regs["ret"], argv[0])
        return
    
    eh.uc.reg_write(eh.regs["ret"], 0)
    
def _strdupHook(eh, address, argv, funcName, userData):
    if eh.isValidEmuPtr(argv[0]):
        s = eh.getEmuString(argv[0])
        memAddr = eh.allocEmuMem(len(s) + 1)
        eh.uc.mem_write(memAddr, s)
        eh.uc.reg_write(eh.regs["ret"], memAddr)
        return
    
    eh.uc.reg_write(eh.regs["ret"], 0)
    
def _wcsdupHook(eh, address, argv, funcName, userData):
    if eh.isValidEmuPtr(argv[0]):
        s = eh.getEmuWideString(argv[0])
        memAddr = eh.allocEmuMem(len(s) + 2)
        eh.uc.mem_write(memAddr, s)
        eh.uc.reg_write(eh.regs["ret"], memAddr)
        return
    
    eh.uc.reg_write(eh.regs["ret"], 0)
    
def _modHook(eh, address, argv, funcName, userData):
    eh.uc.reg_write(eh.regs["ret"], argv[0] % argv[1])
    
def _passHook(eh, address, argv, funcName, userData):
    pass
    
def _freeHook(eh, address, argv, funcName, userData):
    eh.freeEmuMem(argv[0])

def _isalnum(eh, address, argv, funcName, userData):
    if chr(argv[0]).isalnum():
        eh.uc.reg_write(eh.regs["ret"], 1)
    else:
        eh.uc.reg_write(eh.regs["ret"], 0)
   
# used for calls to addresses that are not the start of a function
# call $+5 for example
# simply emulates the call instruction   
def _callHook(eh, address, argv, funcName, userData):
    if eh.arch == unicorn.UC_ARCH_X86:
        eh.stackPush(address + userData["currAddrSize"])
        if eh.analysisHelper.getOpndType(address, 0) == eh.analysisHelper.o_reg:
            target = eh.getRegVal(eh.analysisHelper.getOperand(address, 0))
        else:
            target = eh.analysisHelper.getOpndValue(address, 0)
        eh.uc.reg_write(eh.regs["pc"], target)
        
    elif eh.arch == unicorn.UC_MODE_ARM:
        if eh.analysisHelper.getMnem(address).upper()[:2] == "BL": # BL or BLX
            eh.uc.reg_write(eh.regs["LR"], address + userData["currAddrSize"])
            
        if eh.analysisHelper.getOpndType(address, 0) == eh.analysisHelper.o_reg:
            target = eh.getRegVal(eh.analysisHelper.getOperand(address, 0))
        else:
            target = eh.analysisHelper.getOpndValue(address, 0)
            
        eh.uc.reg_write(eh.regs["pc"], target)
        userData["changeThumbMode"] = True
        
    elif eh.arch == unicorn.UC_MODE_ARM64:
        if eh.analysisHelper.getMnem(address).upper()[:2] == "BL": # BL or BLR
            eh.uc.reg_write(eh.regs["LR"], address + userData["currAddrSize"])
            
        if eh.analysisHelper.getOpndType(address, 0) == eh.analysisHelper.o_reg:
            target = eh.getRegVal(eh.analysisHelper.getOperand(address, 0))
        else:
            target = eh.analysisHelper.getOpndValue(address, 0)
            
        eh.uc.reg_write(eh.regs["pc"], target)
        
CRYPT_STRING_BASE64HEADER = 0
CRYPT_STRING_BASE64 = 1
CRYPT_STRING_BINARY = 2
CRYPT_STRING_BASE64REQUESTHEADER = 3
CRYPT_STRING_HEX = 4
CRYPT_STRING_HEXASCII = 5
CRYPT_STRING_BASE64_ANY = 6
CRYPT_STRING_ANY = 7
CRYPT_STRING_HEX_ANY = 8
CRYPT_STRING_BASE64X509CRLHEADER = 9
CRYPT_STRING_HEXADDR = 10
CRYPT_STRING_HEXASCIIADDR = 11
CRYPT_STRING_HEXRAW = 12
CRYPT_STRING_STRICT = 0x20000000
CRYPT_STRING_NOCRLF = 0x40000000
CRYPT_STRING_NOCR = 0x80000000

def _handleStr2BinBase64Header(s):
    if (not s.startswith("-----BEGIN CERTIFICATE-----\n") or
        not s.endswith("\n-----END CERTIFICATE-----")):
        return None
    s = s[28:-26]
    try:
        return base64.b64decode(s)
    except:   
        return None
    
# these are probably much looser than the real implementations
def _handleStr2BinHex(s):
    re.match(r"[ ]{8}[0-9a-f]{2}", s)
    if m is None:
        return None
    try:
        s = s.replace("\n", "").replace(" ", "")
        return binascii.unhexlify(s)
    except:
        return None
    
def _handleStr2BinHexAscii(s):
    re.match(r"[ ]{8}[0-9a-f]{2}", s)
    if m is None:
        return None
    try:
        # crop off ASCII chars at the end of each line
        s = re.sub(r"^.{8}(.{48}).+$", r"\1", s, flags=re.M)
        s = s.replace("\n", "").replace(" ", "")
        return binascii.unhexlify(s)
    except:
        return None
    
def _handleStr2BinHexAddr(s):
    re.match(r"[0-9a-f ]{8}[0-9a-f]{2}", s)
    if m is None:
        return None
    try:
        # crop off the address chars at the beginning of each line
        s = re.sub(r"^.{8}(.+)$", r"\1", s, flags=re.M)
        s = s.replace("\n", "").replace(" ", "")
        return binascii.unhexlify(s)
    except:
        return None
    
def _handleStr2BinHexAsciiAddr(s):
    re.match(r"[ ]{8}[0-9a-f]{2}", s)
    if m is None:
        return None
    try:
        # crop off ASCII chars at the end of each line
        s = re.sub(r"^.{8}(.{48}).+$", r"\1", s, flags=re.M)
        s = s.replace("\n", "").replace(" ", "")
        return binascii.unhexlify(s)
    except:
        return None

def _handleStr2BinHexRaw(s):
    s = s.replace("\n", "").replace(" ", "")
    try:
        return binascii.unhexlify(s)
    except:
        return None
    
def _handleHookError(eh, address, retval, msg=""):
    if msg == "":
        msg = "no details"
    logging.debug("error in %s hook @%s (%s)" % (inspect.stack()[1][3], eh.hexString(address), msg))
    eh.uc.reg_write(eh.regs["ret"], retval)

def _cryptStringToBinaryA(eh, address, argv, funcName, userData):
    if eh.isValidEmuPtr(argv[0]) and eh.isValidEmuPtr(argv[4]):
        srcLen = argv[1]
        if srcLen != 0:
            src = eh.getEmuBytes(argv[0], srcLen)
        else:
            src = eh.getEmuString(argv[0])
            
        if argv[5] != 0:
            if eh.isValidEmuPtr(argv[5]):
                src = src[eh.getEmuDword(argv[5]):]
            else:
                _handleHookError(eh, address, 0, "pdwSkip is not a valid pointer")
                return
        
        flagUsed = argv[2]
        if argv[2] == CRYPT_STRING_BASE64HEADER:
            enc = _handleStr2BinBase64Header(src)
            if enc is None:
                _handleHookError(eh, address, 0, "CRYPT_STRING_BASE64HEADER")
                return
        elif argv[2] == CRYPT_STRING_BASE64:
            try:
                enc = base64.b64decode(src)
            except:
                _handleHookError(eh, address, 0, "CRYPT_STRING_BASE64")
                return
        elif argv[2] == CRYPT_STRING_BINARY:
            enc = src
        elif argv[2] == CRYPT_STRING_BASE64REQUESTHEADER:
            if (not src.startswith("-----BEGIN NEW CERTIFICATE REQUEST-----\n") or
                not src.endswith("\n-----END NEW CERTIFICATE REQUEST-----")):
                _handleHookError(eh, address, 0, "could not parse CRYPT_STRING_BASE64REQUESTHEADER")
                return
            src = src[40:-38]
            try:
                enc = base64.b64decode(src)
            except:
                _handleHookError(eh, address, 0, "could not decode CRYPT_STRING_BASE64REQUESTHEADER")
                return
        elif argv[2] == CRYPT_STRING_HEX:
            enc = _handleStr2BinHex(src)
            if enc is None:
                _handleHookError(eh, address, 0, "CRYPT_STRING_HEX")
                return
        elif argv[2] == CRYPT_STRING_HEXASCII:
            enc = _handleStr2BinHexAscii(src)
            if enc is None:
                _handleHookError(eh, address, 0, "CRYPT_STRING_HEXASCII")
                return
        elif argv[2] == CRYPT_STRING_BASE64_ANY or argv[2] == CRYPT_STRING_ANY:
            enc = _handleStr2BinBase64Header(src)
            flagUsed = CRYPT_STRING_BASE64HEADER
            if enc == None:
                try:
                    enc = base64.b64decode(src)
                    flagUsed = CRYPT_STRING_BASE64
                except:
                    if argv[2] == CRYPT_STRING_ANY:
                        enc = src
                        flagUsed = CRYPT_STRING_BINARY
                    else:
                        _handleHookError(eh, address, 0, "none of the Base64/String cases succeeded for ANY")
                        return
        elif argv[2] == CRYPT_STRING_HEX_ANY:
            enc = _handleStr2BinHexAddr(src)
            flagUsed = CRYPT_STRING_HEXADDR
            if enc is None:
                enc = _handleStr2BinHexAsciiAddr(src)
                flagUsed = CRYPT_STRING_HEXASCIIADDR
                if enc is None:
                    enc = _handleStr2BinHex(src)
                    flagUsed = CRYPT_STRING_HEX
                    if enc is None:
                        enc = _handleStr2BinHexRaw(src)
                        flagUsed = CRYPT_STRING_HEXRAW
                        if enc is None:
                            enc = _handleStr2BinHexAscii(src)
                            flagUsed = CRYPT_STRING_HEXASCII
                            if enc is None:
                                _handleHookError(eh, address, 0, "none of the hex cases succeeded for ANY")
                                return    
        elif argv[2] == CRYPT_STRING_BASE64X509CRLHEADER:
            if (not src.startswith("-----BEGIN X509 CRL-----\n") or
                not src.endswith("\n-----END X509 CRL-----")):
                _handleHookError(eh, address, 0, "could not parse CRYPT_STRING_BASE64X509CRLHEADER")
                return
            src = src[25:-23]
            try:
                enc = base64.b64decode(src)
            except:
                _handleHookError(eh, address, 0, "could not decode CRYPT_STRING_BASE64X509CRLHEADER")
                return
        elif argv[2] == CRYPT_STRING_HEXADDR:
            enc = _handleStr2BinHexAddr(src)
            if enc is None:
                _handleHookError(eh, address, 0, "CRYPT_STRING_HEXADDR")
                return
        elif argv[2] == CRYPT_STRING_HEXASCIIADDR:
            enc = _handleStr2BinHexAsciiAddr(src)
            if enc is None:
                _handleHookError(eh, address, 0, "CRYPT_STRING_HEXASCIIADDR")
                return
        elif argv[2] == CRYPT_STRING_HEXRAW:
            enc = _handleStr2BinHexRaw(src)
            if enc is None:
                _handleHookError(eh, address, 0, "CRYPT_STRING_HEXRAW")
                return
        
        if argv[6] != 0 and eh.isValidEmuPtr(argv[6]):
            eh.writeEmuDword(argv[6], flagUsed)  
      
        dstSize = eh.getEmuDword(argv[4])
        eh.writeEmuDword(argv[4], len(enc))
        if argv[3] == 0:
            eh.uc.reg_write(eh.regs["ret"], 1)
            return
        
        if dstSize < len(enc):
            _setLastError(eh, address, [flare_emu.ERROR_MORE_DATA], funcName, userData)
            _handleHookError(eh, address, 0, "ERROR_MORE_DATA")
            return
            
        dstRegion = eh.getEmuMemRegion(argv[3])
        maxBufSize = eh._checkMemSize(dstSize, userData)
        if dstRegion is None:
            logging.debug("dest memory does not exist for CryptStringToBinaryA @%s" % eh.hexString(address))
            dstRegion = eh.getEmuMemRegion(eh.allocEmuMem(maxBufSize))
            argv[3] = dstRegion[0]
        
        eh.uc.mem_write(argv[3], enc)
        eh.uc.reg_write(eh.regs["ret"], 1)
        return

    eh.uc.reg_write(eh.regs["ret"], 0)
    
def hexdump(data, addrs=False, ascii=False):
    out = ""
    offs = 0
    hexed = binascii.hexlify(data)
    for line in (hexed[i:i+32] for i in range(0, len(hexed), 32)):
        line = " ".join(line[j:j+2] for j in range(0, len(line), 2))
        if addrs:
            prefix = "%04x" % offs
            prefix = prefix.ljust(8, ' ')
        else:
            prefix = " " * 8
        
        line = prefix + line[:24] + " " + line[24:]
        
        # crop off middle space if less than 8 bytes on line
        if len(data) - offs < 8:
            line = line[:-1]
        
        if ascii:
            line = line.ljust(59, ' ')
            suffix = ""
            for c in data[offs:offs+16]:
                if 0x20 <= ord(c) <= 0x7e:
                    suffix += c
                else:
                    suffix += "."
                    
            line += suffix
            
        out += line + "\n"
        offs += 0x10
        
    return out
    
def _cryptBinaryToStringA(eh, address, argv, funcName, userData):
    if eh.isValidEmuPtr(argv[0]) and eh.isValidEmuPtr(argv[4]):
        srcLen = argv[1]
        src = eh.getEmuBytes(argv[0], srcLen)
        flagsLower = argv[2] & 0xffff
        flagsUpper = argv[2] & 0xffff0000
        if flagsLower == CRYPT_STRING_BASE64HEADER:
            enc = base64.b64encode(src)
            enc = "-----BEGIN CERTIFICATE-----\n" + enc + "\n-----END CERTIFICATE-----"
        elif flagsLower == CRYPT_STRING_BASE64:
            enc = base64.b64encode(src)
        elif flagsLower == CRYPT_STRING_BINARY:
            enc = src
        elif flagsLower == CRYPT_STRING_BASE64REQUESTHEADER:
            enc = base64.b64encode(src)
            enc = "-----BEGIN NEW CERTIFICATE REQUEST-----\n" + enc + "\n-----END NEW CERTIFICATE REQUEST-----"
        elif flagsLower == CRYPT_STRING_HEX:
            enc = hexdump(src)
        elif flagsLower == CRYPT_STRING_HEXASCII:
            enc = hexdump(src, ascii=True)
        elif flagsLower == CRYPT_STRING_BASE64X509CRLHEADER:
            enc = base64.b64encode(src)
            enc = "-----BEGIN X509 CRL-----\n" + enc + "\n-----END X509 CRL-----"
        elif flagsLower == CRYPT_STRING_HEXADDR:
            enc = hexdump(src, addrs=True)
        elif flagsLower == CRYPT_STRING_HEXASCIIADDR:
            enc = hexdump(src, True, True)
        elif flagsLower == CRYPT_STRING_HEXRAW:
            src = binascii.hexlify(src)
            enc = " ".join(src[i:i+2] for i in range(0, len(src), 2))
            
        #TODO: handle ending newline flags
      
        dstSize = eh.getEmuDword(argv[4])
        eh.writeEmuDword(argv[4], len(enc))
        if argv[3] == 0:
            eh.uc.reg_write(eh.regs["ret"], 1)
            return
        
        if dstSize < len(enc):
            _setLastError(eh, address, [flare_emu.ERROR_MORE_DATA], funcName, userData)
            _handleHookError(eh, address, 0, "ERROR_MORE_DATA")
            return
            
        dstRegion = eh.getEmuMemRegion(argv[3])
        maxBufSize = eh._checkMemSize(dstSize, userData)
        if dstRegion is None:
            logging.debug("dest memory does not exist for CryptBinaryToStringA @%s" % eh.hexString(address))
            dstRegion = eh.getEmuMemRegion(eh.allocEmuMem(maxBufSize))
            argv[3] = dstRegion[0]
        
        eh.uc.mem_write(argv[3], enc)
        eh.uc.reg_write(eh.regs["ret"], 1)
        return

    eh.uc.reg_write(eh.regs["ret"], 0)
    
# def _cryptStringToBinaryW(eh, address, argv, funcName, userData):
    
