import re

import idaapi
import idautils
import idc
import ida_ida

import flare_emu

# wrappers for IDA Pro (IDAPython) 7, 8 and 9 compability
version = float(idaapi.get_kernel_version())
if version < 9.0:

    def get_filetype() -> "ida_ida.filetype_t":
        return idaapi.get_inf_structure().filetype

    def get_processor_name() -> str:
        return idaapi.get_inf_structure().procname

    def is_32bit() -> bool:
        info: idaapi.idainfo = idaapi.get_inf_structure()
        return info.is_32bit()

    def is_64bit() -> bool:
        info: idaapi.idainfo = idaapi.get_inf_structure()
        return info.is_64bit()

else:

    def get_filetype() -> "ida_ida.filetype_t":
        return ida_ida.inf_get_filetype()

    def get_processor_name() -> str:
        return idc.get_processor_name()

    def is_32bit() -> bool:
        return idaapi.inf_is_32bit_exactly()

    def is_64bit() -> bool:
        return idaapi.inf_is_64bit()


class IdaProAnalysisHelper(flare_emu.AnalysisHelper):
    def __init__(self, eh):
        super(IdaProAnalysisHelper, self).__init__()
        self.eh = eh
        if get_processor_name() == "metapc":
            self.arch = "X86"
        else:
            self.arch = get_processor_name()
        if is_64bit():
            self.bitness = 64
        elif is_32bit():
            self.bitness = 32
        else:
            self.bitness = None
        filetype = get_filetype()
        if filetype == idaapi.f_PE:
            self.filetype = "PE"
        elif filetype == idaapi.f_MACHO:
            self.filetype = "MACHO"
        elif filetype == idaapi.f_ELF:
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

    def getFuncName(self, addr, normalized=True):
        if normalized:
            return self.normalizeFuncName(idc.get_func_name(addr))
        else:
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

    def getMinimumAddr(self):
        return idc.get_inf_attr(idc.INF_MIN_EA)

    def getMaximumAddr(self):
        return idc.get_inf_attr(idc.INF_MAX_EA)

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

    def getSegmentName(self, addr):
        return idc.get_segm_name(addr)

    def getSegmentStart(self, addr):
        return idc.get_segm_start(addr)

    def getSegmentEnd(self, addr):
        return idc.get_segm_end(addr)

    def getSegmentDefinedSize(self, addr):
        size = 0
        segEnd = self.getSegmentEnd(addr)
        addr = self.getSegmentStart(addr)
        while idc.has_value(idc.get_full_flags(addr)):
            if addr >= segEnd:
                break
            size += 1
            addr += 1
        return size

    def getSegments(self):
        return idautils.Segments()

    def getSegmentSize(self, addr):
        return self.getSegmentEnd(addr) - self.getSegmentStart(addr)

    def getSectionName(self, addr):
        return self.getSegmentName(addr)

    def getSectionStart(self, addr):
        return self.getSegmentStart(addr)

    def getSectionEnd(self, addr):
        return self.getSegmentEnd(addr)

    def getSectionSize(self, addr):
        return self.getSegmentSize(addr)

    def getSections(self):
        return self.getSegments()

    # gets disassembled instruction with names and comments as a string
    def getDisasmLine(self, addr):
        return idc.generate_disasm_line(addr, 0)

    def getName(self, addr):
        return idc.get_name(addr, idc.ida_name.GN_VISIBLE)

    def getNameAddr(self, name):
        name = idc.get_name_ea_simple(name)
        if name == "":
            name = idc.get_name_ea_simple(self.normalizeFuncName(name))
        return name

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
        return list(map(lambda x: x.frm, list(idautils.XrefsTo(addr))))

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

    def normalizeFuncName(self, funcName):
        # remove appended _n from IDA Pro names
        if funcName.startswith("sub_") or funcName.startswith("loc_"):
            return funcName
        funcName = re.sub(r"_[\d]+$", "", funcName)
        return funcName
