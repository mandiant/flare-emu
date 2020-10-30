import flare_emu

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
        eh.logger.debug("dest memory does not exist for memcpy @%s" % eh.hexString(address))
        dstRegion = eh.getEmuMemRegion(eh.allocEmuMem(copySize))
        argv[0] = dstRegion[0]
    if srcRegion is None:
        eh.logger.debug("source memory does not exist for memcpy @%s" % eh.hexString(address))
    else:
        if copySize <= srcRegion[1] - argv[1] and copySize <= dstRegion[1] - argv[0]:
            eh.copyEmuMem(argv[0], argv[1], copySize, userData)
        else:
            eh.logger.debug("dest memory not large enough @%s" % eh.hexString(address))
    eh.uc.reg_write(eh.regs["ret"], argv[0])
    
def _strlenHook(eh, address, argv, funcName, userData):
    if eh.isValidEmuPtr(argv[0]):
        eh.uc.reg_write(eh.regs["ret"], len(eh.getEmuString(argv[0])))
    else:
        eh.uc.reg_write(eh.regs["ret"], 0)
        
def _wcslenHook(eh, address, argv, funcName, userData):
    if eh.isValidEmuPtr(argv[0]):
        eh.uc.reg_write(eh.regs["ret"], len(eh.getEmuWideString(argv[0]).decode("utf-16le") ))
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
        strlen = len(eh.getEmuWideString(argv[0]).decode("utf-16le"))
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
        str1 = eh.getEmuWideString(argv[1]).decode("utf-16le")
        str2 = eh.getEmuWideString(argv[0]).decode("utf-16le")
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
        str1 = eh.getEmuWideString(argv[1]).decode("utf-16le")
        str2 = eh.getEmuWideString(argv[0]).decode("utf-16le")
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
        str1 = eh.getEmuWideString(argv[1]).decode("utf-16le")
        str2 = eh.getEmuWideString(argv[0]).decode("utf-16le")
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
        str1 = eh.getEmuWideString(argv[1]).decode("utf-16le")
        str2 = eh.getEmuWideString(argv[0]).decode("utf-16le")
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
        src = eh.getEmuString(argv[1]) + b"\x00"
        dstRegion = eh.getEmuMemRegion(argv[0])
        if dstRegion is None:
            eh.logger.debug("dest memory does not exist for strcpy @%s" % eh.hexString(address))
            dstRegion = eh.getEmuMemRegion(eh.allocEmuMem(len(src)))
            argv[0] = dstRegion[0]
        if len(src) <= dstRegion[1] - argv[0]:
            eh.writeEmuMem(argv[0], src)
            eh.uc.reg_write(eh.regs["ret"], argv[0])
            return
        else:
            eh.logger.debug("dest memory not large enough @%s" % eh.hexString(address))

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
            eh.logger.debug("dest memory does not exist for strncpy @%s" % eh.hexString(address))
            dstRegion = eh.getEmuMemRegion(eh.allocEmuMem(strnlen))
            argv[0] = dstRegion[0]
        if strnlen <= dstRegion[1] - argv[0]:
            if strnlen > len(src):
                src = src.ljust(strnlen, b"\x00") 
            eh.writeEmuMem( argv[0], src)
            eh.uc.reg_write( eh.regs["ret"], argv[0] )
            return
        else:
            eh.logger.debug("dest memory not large enough @%s" % eh.hexString(address))

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
            eh.logger.debug("dest memory does not exist for strncpy_s @%s" % eh.hexString(address))
            dstRegion = eh.getEmuMemRegion(eh.allocEmuMem(strnlen))
            argv[0] = dstRegion[0]
        
        strnlen = min(strnlen, len(src))
        if strnlen + 1 <= dstRegion[1] - argv[0]:
            eh.writeEmuMem(argv[0], src + b"\x00")
            eh.uc.reg_write(eh.regs["ret"], 0)
            return
        else:
            eh.logger.debug("dest memory not large enough @%s" % eh.hexString(address))

    if eh.size_pointer == 8:
        val = 0xffffffffffffffff
    else:
        val = 0xffffffff
    eh.uc.reg_write(eh.regs["ret"], val)
   
def _wcscpyHook(eh, address, argv, funcName, userData):
    if eh.isValidEmuPtr(argv[1]):
        src = eh.getEmuWideString(argv[1]) + b"\x00\x00"
        dstRegion = eh.getEmuMemRegion(argv[0])
        if dstRegion is None:
            eh.logger.debug("dest memory does not exist for wcscpy @%s" % eh.hexString(address))
            dstRegion = eh.getEmuMemRegion(eh.allocEmuMem(len(src)))
            argv[0] = dstRegion[0]
        if len(src) <= dstRegion[1] - argv[0]:
            eh.writeEmuMem(argv[0], src)
            eh.uc.reg_write(eh.regs["ret"], argv[0])
            return
        else:
            eh.logger.debug("dest memory not large enough @%s" % eh.hexString(address))

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
            eh.logger.debug("dest memory does not exist for wcsncpy @%s" % eh.hexString(address))
            dstRegion = eh.getEmuMemRegion(eh.allocEmuMem(strnlen))
            argv[0] = dstRegion[0]
        if strnlen <= dstRegion[1] - argv[0]:
            if strnlen > len(src):
                src = src.ljust(strnlen, b"\x00")
            eh.writeEmuMem(argv[0], src)
            eh.uc.reg_write(eh.regs["ret"], argv[0])
            return
        else:
            eh.logger.debug("dest memory not large enough @%s" % eh.hexString(address))

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
            eh.logger.debug("dest memory does not exist for wcsncpy_s @%s" % eh.hexString(address))
            dstRegion = eh.getEmuMemRegion(eh.allocEmuMem(strnlen))
            argv[0] = dstRegion[0]
            
        strnlen = min(strnlen, len(src))
        if strnlen + 2 <= dstRegion[1] - argv[0]:
            src = src[:strnlen] + b"\x00\x00"
            eh.writeEmuMem(argv[0], src)
            eh.uc.reg_write(eh.regs["ret"], 0)
            return
        else:
            eh.logger.debug("dest memory not large enough @%s" % eh.hexString(address))

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
        buf = eh.uc.mem_read(argv[0], srchlen)
        offs = buf.find(srch)
        if offs > -1:
            eh.uc.reg_write(eh.regs["ret"], argv[0] + offs)
            return
            
    eh.uc.reg_write(eh.regs["ret"], 0)
    
def _mbtowcHook(eh, address, argv, funcName, userData):
    if eh.isValidEmuPtr(argv[1]):
        src = eh.getEmuString(argv[1]).decode("latin1")[0]
        dstRegion = eh.getEmuMemRegion(argv[0])
        if dstRegion is None:
            eh.logger.debug("dest memory does not exist for mbtowc variant @%s" % eh.hexString(address))
            dstRegion = eh.getEmuMemRegion(eh.allocEmuMem(0x1000))
            argv[0] = dstRegion[0]
        eh.writeEmuMem(argv[0], src.encode("utf-16le")[0:2] + b"\x00\x00")
        eh.uc.reg_write(eh.regs["ret"], 1)
        return

    eh.uc.reg_write(eh.regs["ret"], 0)
    
def _mbstowcsHook(eh, address, argv, funcName, userData):
    if eh.isValidEmuPtr(argv[1]):
        maxBufSize = eh._checkMemSize(argv[2] * 2, userData)
        src = eh.getEmuString(argv[1])
        if len(src) < argv[2]:
            src += b"\x00"
        else:
            src = src[:argv[2]]
        dstRegion = eh.getEmuMemRegion(argv[0])
        if dstRegion is None:
            eh.logger.debug("dest memory does not exist for mbtowc variant @%s" % eh.hexString(address))
            dstRegion = eh.getEmuMemRegion(eh.allocEmuMem(maxBufSize))
            argv[0] = dstRegion[0]
        if len(src) * 2 + 2 <= dstRegion[1] - argv[0]:
            eh.writeEmuMem(argv[0], src.decode("latin1").encode("utf-16le") + b"\x00\x00")
            eh.uc.reg_write(eh.regs["ret"], len(src.replace(b"\x00", b"")))
            return
        else:
            eh.logger.debug("dest memory not large enough @%s" % eh.hexString(address))

    eh.uc.reg_write(eh.regs["ret"], 0)
    
def _wctombHook(eh, address, argv, funcName, userData):
    if eh.isValidEmuPtr(argv[1]):
        src = eh.getEmuWideString(argv[1]).decode("utf-16le")
        dstRegion = eh.getEmuMemRegion(argv[0])
        if dstRegion is None:
            eh.logger.debug("dest memory does not exist for wctomb variant @%s" % eh.hexString(address))
            dstRegion = eh.getEmuMemRegion(eh.allocEmuMem(0x1000))
        argv[0] = dstRegion[0]
        eh.writeEmuMem(argv[0], src[0].encode("utf-16le"))
        eh.uc.reg_write(eh.regs["ret"], 1)
        return

    eh.uc.reg_write(eh.regs["ret"], 0)
    
def _wcstombsHook(eh, address, argv, funcName, userData):
    if eh.isValidEmuPtr(argv[1]):
        bufSize = eh._checkMemSize(argv[2], userData)
        src = eh.getEmuWideString(argv[1]).decode("utf-16le")
        if len(src) < argv[2]:
            src += "\x00"
        else:
            src = src[:argv[2]]
        dstRegion = eh.getEmuMemRegion(argv[0])
        if dstRegion is None:
            eh.logger.debug("dest memory does not exist for wctomb variant @%s" % eh.hexString(address))
            dstRegion = eh.getEmuMemRegion(eh.allocEmuMem(bufSize))
            argv[0] = dstRegion[0]
        if bufSize + 1 <= dstRegion[1] - argv[0]:
            if bufSize > len(src):
                src = src.ljust(bufSize, "\x00")
            eh.writeEmuMem(argv[0], (src + "\x00").encode("utf-16le") )
            eh.uc.reg_write(eh.regs["ret"], len(src.replace("\x00", "")))
            return
        else:
            eh.logger.debug("dest memory not large enough @%s" % eh.hexString(address))

    eh.uc.reg_write(eh.regs["ret"], 0)
    
def _multiByteToWideCharHook(eh, address, argv, funcName, userData):
    if eh.isValidEmuPtr(argv[2]):
        src = eh.getEmuString(argv[2])
        srcLen = eh.getSignedValue(argv[3])
        if srcLen == -1:
            src += b"\x00"
            maxBufSize = eh._checkMemSize(len(src) * 2, userData)
        else:
            maxBufSize = eh._checkMemSize(srcLen * 2, userData)
        
        if len(src) < srcLen:
            src += b"\x00"
        elif srcLen != -1:
            src = src[:srcLen]
            
        if argv[5] == 0:
            eh.uc.reg_write(eh.regs["ret"], len(src) * 2)
            return
        dstRegion = eh.getEmuMemRegion(argv[4])
        if dstRegion is None:
            eh.logger.debug("dest memory does not exist for mbtowc variant @%s" % eh.hexString(address))
            dstRegion = eh.getEmuMemRegion(eh.allocEmuMem(maxBufSize))
            argv[4] = dstRegion[0]
        if len(src) * 2 + 2 <= dstRegion[1] - argv[4]:
            eh.writeEmuMem(argv[4], src.decode("latin1").encode("utf-16le") + b"\x00\x00")
            eh.uc.reg_write(eh.regs["ret"], len(src))
            return
        else:
            eh.logger.debug("dest memory not large enough @%s" % eh.hexString(address))

    eh.uc.reg_write(eh.regs["ret"], 0)
    
def _wideCharToMultiByteHook(eh, address, argv, funcName, userData):
    if eh.isValidEmuPtr(argv[2]):
        src = eh.getEmuWideString(argv[2]).decode("utf-16le")
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
            eh.logger.debug("dest memory does not exist for mbtowc variant @%s" % eh.hexString(address))
            dstRegion = eh.getEmuMemRegion(eh.allocEmuMem(maxBufSize))
            argv[4] = dstRegion[0]
        if len(src) + 1 <= dstRegion[1] - argv[4]:
            eh.writeEmuMem(argv[4], (src + "\x00").encode("latin1") )
            eh.uc.reg_write(eh.regs["ret"], len(src))
            return
        else:
            eh.logger.debug("dest memory not large enough @%s" % eh.hexString(address))

    eh.uc.reg_write(eh.regs["ret"], 0)
    
def _memsetHook(eh, address, argv, funcName, userData):
    setSize = argv[2]
    setSize = eh._checkMemSize(setSize, userData)
    dstRegion = eh.getEmuMemRegion(argv[0])
    src = chr(argv[1] & 0xFF).encode("latin1")
    if dstRegion is None:
        eh.logger.debug("dest memory does not exist for memset @%s" % eh.hexString(address))
        dstRegion = eh.getEmuMemRegion(eh.allocEmuMem(setSize))
        argv[0] = dstRegion[0]
    if setSize <= dstRegion[1] - argv[0]:
        eh.writeEmuMem(argv[0], src * setSize)
    else:
        eh.logger.debug("dest memory not large enough @%s" % eh.hexString(address))
    eh.uc.reg_write(eh.regs["ret"], argv[0])

def _bzeroHook(eh, address, argv, funcName, userData):
    setSize = argv[1]
    setSize = eh._checkMemSize(setSize, userData)
    dstRegion = eh.getEmuMemRegion(argv[0])
    src = b"\x00"
    if dstRegion is None:
        eh.logger.debug("dest memory does not exist for memset @%s" % eh.hexString(address))
        dstRegion = eh.getEmuMemRegion(eh.allocEmuMem(setSize))
        argv[0] = dstRegion[0]
    if setSize <= dstRegion[1] - argv[0]:
        eh.writeEmuMem(argv[0], src * setSize)
    else:
        eh.logger.debug("dest memory not large enough @%s" % eh.hexString(address))
    eh.uc.reg_write(eh.regs["ret"], argv[0])
    
def _strcatHook(eh, address, argv, funcName, userData):
    if eh.isValidEmuPtr(argv[1]):
        src = eh.getEmuString(argv[1]) + b"\x00"
        dstRegion = eh.getEmuMemRegion(argv[0])
        if dstRegion is None:
            eh.logger.debug("dest memory does not exist for strcat @%s" % eh.hexString(address))
            dstRegion = eh.getEmuMemRegion(eh.allocEmuMem(len(src) + 1))
            argv[0] = dstRegion[0]
        dst = eh.getEmuString(argv[0])
        if len(dst) + len(src) <= dstRegion[1] - argv[0]:
            eh.writeEmuMem( argv[0], dst + src )
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
            eh.logger.debug("dest memory does not exist for strncat @%s" % eh.hexString(address))
            dstRegion = eh.getEmuMemRegion(eh.allocEmuMem(strnlen + 1))
            argv[0] = dstRegion[0]
        dst = eh.getEmuString(argv[0])
        if len(dst) + strnlen + 1 <= dstRegion[1] - argv[0]:
            eh.writeEmuMem(argv[0], dst + src[:strnlen] + b"\x00" )
            eh.uc.reg_write(eh.regs["ret"], argv[0])
            return

    eh.uc.reg_write(eh.regs["ret"], 0)

def _wcscatHook(eh, address, argv, funcName, userData):
    if eh.isValidEmuPtr(argv[1]):
        src = eh.getEmuWideString(argv[1]) + b"\x00\x00"
        dstRegion = eh.getEmuMemRegion(argv[0])
        if dstRegion is None:
            eh.logger.debug("dest memory does not exist for wcscat @%s" % eh.hexString(address))
            dstRegion = eh.getEmuMemRegion(eh.allocEmuMem(len(src)))
            argv[0] = dstRegion[0]
        dst = eh.getEmuWideString(argv[0])
        if len(dst) + len(src) <= dstRegion[1] - argv[0]:
            eh.writeEmuMem(argv[0], dst + src )
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
            eh.logger.debug("dest memory does not exist for wcsncat @%s" % eh.hexString(address))
            dstRegion = eh.getEmuMemRegion(eh.allocEmuMem(strnlen + 2))
            argv[0] = dstRegion[0]
        dst = eh.getEmuWideString(argv[0])
        if len(dst) + strnlen + 2 <= dstRegion[1] - argv[0]:
            eh.writeEmuMem(argv[0], dst + src[:strnlen] + b"\x00\x00")
            eh.uc.reg_write(eh.regs["ret"], argv[0])
            return

    eh.uc.reg_write(eh.regs["ret"], 0)
    
def _strchrHook(eh, address, argv, funcName, userData):
    if eh.isValidEmuPtr(argv[0]):
        s = eh.getEmuString(argv[0]).decode("latin1")
        idx = s.find(chr(argv[1] & 0xFF))
        if idx != -1:
            eh.uc.reg_write(eh.regs["ret"], argv[0] + idx)
            return

    eh.uc.reg_write(eh.regs["ret"], 0)

def _wcschrHook(eh, address, argv, funcName, userData):
    if eh.isValidEmuPtr(argv[0]):
        s = eh.getEmuWideString(argv[0]).decode("utf-16le")
        idx = s.find(chr(argv[1] & 0xFF))
        if idx != -1:
            eh.uc.reg_write(eh.regs["ret"], argv[0] + idx * 2)
            return

    eh.uc.reg_write(eh.regs["ret"], 0)

def _strrchrHook(eh, address, argv, funcName, userData):
    if eh.isValidEmuPtr(argv[0]):
        s = eh.getEmuString(argv[0]).decode("latin1")
        idx = s.rfind(chr(argv[1] & 0xFF))
        if idx != -1:
            eh.uc.reg_write(eh.regs["ret"], argv[0] + idx)
            return
    
    eh.uc.reg_write(eh.regs["ret"], 0)
        
def _wcsrchrHook(eh, address, argv, funcName, userData):
    if eh.isValidEmuPtr(argv[0]):
        s = eh.getEmuWideString(argv[0]).decode("utf-16le")
        idx = s.rfind(chr(argv[1] & 0xFF))
        if idx != -1:
            eh.uc.reg_write(eh.regs["ret"], argv[0] + idx * 2)
            return

    eh.uc.reg_write(eh.regs["ret"], 0)
    
def _strlwrHook(eh, address, argv, funcName, userData):
    if eh.isValidEmuPtr(argv[0]):
        s = eh.getEmuString(argv[0]).decode("latin1")
        eh.writeEmuMem(argv[0], s.lower().encode("latin1"))
        eh.uc.reg_write(eh.regs["ret"], argv[0])
        return
    
    eh.uc.reg_write(eh.regs["ret"], 0)
    
def _struprHook(eh, address, argv, funcName, userData):
    if eh.isValidEmuPtr(argv[0]):
        s = eh.getEmuString(argv[0]).decode("latin1")
        eh.writeEmuMem(argv[0], s.upper().encode("latin1"))
        eh.uc.reg_write(eh.regs["ret"], argv[0])
        return
    
    eh.uc.reg_write(eh.regs["ret"], 0)
    
def _wcslwrHook(eh, address, argv, funcName, userData):
    if eh.isValidEmuPtr(argv[0]):
        s = eh.getEmuWideString(argv[0]).decode("utf-16le")
        eh.writeEmuMem(argv[0], s.lower().encode("utf-16le"))
        eh.uc.reg_write(eh.regs["ret"], argv[0])
        return
    
    eh.uc.reg_write(eh.regs["ret"], 0)
    
def _wcsuprHook(eh, address, argv, funcName, userData):
    if eh.isValidEmuPtr(argv[0]):
        s = eh.getEmuWideString(argv[0]).decode("utf-16le")
        eh.writeEmuMem(argv[0], s.upper().encode("utf-16le"))
        eh.uc.reg_write(eh.regs["ret"], argv[0])
        return
    
    eh.uc.reg_write(eh.regs["ret"], 0)
    
def _strdupHook(eh, address, argv, funcName, userData):
    if eh.isValidEmuPtr(argv[0]):
        s = eh.getEmuString(argv[0])
        memAddr = eh.allocEmuMem(len(s) + 1)
        eh.writeEmuMem(memAddr, s)
        eh.uc.reg_write(eh.regs["ret"], memAddr)
        return
    
    eh.uc.reg_write(eh.regs["ret"], 0)
    
def _wcsdupHook(eh, address, argv, funcName, userData):
    if eh.isValidEmuPtr(argv[0]):
        s = eh.getEmuWideString(argv[0])
        memAddr = eh.allocEmuMem(len(s) + 2)
        eh.writeEmuMem(memAddr, s)
        eh.uc.reg_write(eh.regs["ret"], memAddr)
        return
    
    eh.uc.reg_write(eh.regs["ret"], 0)
    
def _modHook(eh, address, argv, funcName, userData):
    eh.uc.reg_write(eh.regs["ret"], argv[0] % argv[1])