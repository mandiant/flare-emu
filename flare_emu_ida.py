import idc
import idaapi
import idautils
import flare_emu

class IdaProAnalysisHelper(flare_emu.AnalysisHelper):
    def __init__(self):
        super(IdaProAnalysisHelper, self).__init__()
        self.minimumAddr = idc.get_inf_attr(idc.INF_MIN_EA)
        self.maximumAddr = idc.get_inf_attr(idc.INF_MAX_EA)
        info = idaapi.get_inf_structure()
        if info.procName == "metapc":
            self.arch = "X86"
        else:
            self.arch = info.procName
        if info.is_64bit():
            self.bitness = 64
        elif info.is_32bit():    
            self.bitness = 32
        else:
            self.bitness = None
        if info.filetype == 11:
            self.filetype = "PE"
        elif info.filetype == 25:
            self.filetype = "MACHO"
        elif info.filetype == 18:
            self.filetype = "ELF"
        else:
            self.filetype = "UNKNOWN"

    def getFuncStart(self, addr):
        ret = idc.get_func_attr(addr, idc.FUNCATTR_START)
        if ret == idc.BADADDR:
            return None
        return ret

    def getFuncEnd(self, addr):
        ret =  idc.get_func_attr(addr, idc.FUNCATTR_END)
        if ret == idc.BADADDR:
            return None
        return ret

    def getFuncName(self, addr):
        return idc.get_func_name(addr)

    def getMnem(self, addr):
        return idc.print_insn_mnem(addr)

    def _getBlockByAddr(self, addr, flowchart):
        for bb in flowchart:
            if (addr >= bb.start_ea and addr < bb.end_ea) or addr == bb.start_ea:
                return bb
        return None

    # gets address of last instruction in the basic block containing addr
    def getBlockEndInsnAddr(self, addr, flowchart):
        bb = self._getBlockByAddr(addr, flowchart)
        return idc.prev_head(bb.end_ea, idc.get_inf_attr(idc.INF_MIN_EA))

    def skipJumpTable(self, addr):
        pass

    def getMininumAddr(self):
        return self.minimumAddr

    def getMaximumAddr(self):
        return self.maximumAddr

    def getBytes(self, addr, size):
        return idc.get_bytes(addr, size, False)

    def getCString(self, addr):
        buf = ""
        while self.getBytes(addr, 1) != "\x00" and self.getBytes(addr, 1) is not None:
            buf += self.getBytes(addr, 1)
            addr += 1

        return buf

    def getOperand(self, addr, opndNum):
        return idc.print_operand(addr, opndNum)

    def getWordValue(self, addr):
        return idc.get_wide_word(addr)

    def getDwordValue(self, addr):
        return idc.get_wide_dword(addr)

    def getQWordValue(self, addr):
        return idc.get_qword(addr)

    def isThumbMode(self, addr):
        return idc.get_sreg(addr, "T") == 1

    def getSegName(self, addr):
        return idc.get_segm_name(addr)

    def getSegStart(self, addr):
        return idc.get_segm_start(addr)

    def getSegEnd(self, addr):
        return idc.get_segm_end(addr)

    def getSegSize(self, addr, segEnd):
        size = 0
        while idc.has_value(idc.get_full_flags(addr)):
            if addr >= segEnd:
                break
            size += 1
            addr += 1
        return size


    def getSegments(self):
        return idautils.Segments()

    # gets disassembled instruction with names and comments as a string
    def getDisasmLine(self, addr):
        return idc.generate_disasm_line(addr, 0)

    def getName(self, addr):
        return idc.get_name(addr, idc.ida_name.GN_VISIBLE)

    def getNameAddr(self, name):
        return idc.get_name_ea_simple(name)

    def getOpndType(self, addr, opndNum):
        return idc.get_operand_type(addr, opndNum)

    def getOpndValue(self, addr, opndNum):
        return idc.get_operand_value(addr, opndNum)

    def makeInsn(self, addr):
        if idc.create_insn(addr) == 0:
            idc.del_items(addr, idc.DELIT_EXPAND)
            idc.create_insn(addr)
        idc.auto_wait()

    def createFunction(self, addr):
        pass

    def getFlowChart(self, addr):
        function = idaapi.get_func(addr)
        return list(idaapi.FlowChart(function))


    def getSpDelta(self, addr):
        f = idaapi.get_func(addr)
        return idaapi.get_sp_delta(f, addr)

    def getXrefsTo(self, addr):
        return map(lambda x: x.frm, list(idautils.XrefsTo(addr)))

    def getArch(self):
        return self.arch

    def getBitness(self):
        return self.bitness

    def getFileType(self):
        return self.filetype

    def getInsnSize(self, addr):
        return idc.get_item_size(addr)

    def isTerminatingBB(self, bb):
        if (bb.type == idaapi.fcb_ret or bb.type == idaapi.fcb_noret or
                (bb.type == idaapi.fcb_indjump and len(list(bb.succs())) == 0)):
            return True
        for b in bb.succs():
            if b.type == idaapi.fcb_extern:
                return True

        return False
        
    def skipJumpTable(self, addr):
        while idc.print_insn_mnem(addr) == "":
            addr = idc.next_head(addr, idc.get_inf_attr(idc.INF_MAX_EA))
        return addr

    def setName(self, addr, name, size=0):
        idc.set_name(addr, name, idc.SN_NOCHECK)
    
    def setComment(self, addr, comment, repeatable=False):
        idc.set_cmt(addr, comment, repeatable)