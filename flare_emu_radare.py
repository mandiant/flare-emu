import r2pipe
import binascii
import struct
import flare_emu
import re
import ntpath
import base64
import logging

class BasicBlock():
    def __init__(self, flowchart, id, addr, size, jump, fail):
        self.start_ea = addr
        self.size = size
        self.end_ea = addr + size
        self.successors = [fail, jump]
        self.type = -1
        self.id = id
        self.flowchart = flowchart

    def succs(self):
        for z in map(lambda x: self.getBlockByAddr(x), filter(lambda y: y != -1, self.successors)):
            yield z

    def getBlockByAddr(self, addr):
        for bb in self.flowchart:
            if addr >= bb.start_ea and addr < bb.end_ea:
                return bb

class Radare2AnalysisHelper(flare_emu.AnalysisHelper):
    # def __init__(self, path, useProjects=True, projectName=None):
    def __init__(self, path, eh):
        super(Radare2AnalysisHelper, self).__init__()
        try:
            self.eh = eh
            self.r = r2pipe.open(path)
            self.path = path
        except:
            print("error loading %s in radare2" % path)
            exit(1)

        info = self.r.cmdj("iAj")
        self.arch = info['bins'][0]['arch'].upper()
        self.bitness = info['bins'][0]['bits']
        self.filetype = self.r.cmdj("ij")['core']['format'].upper()
        
        if self.filetype[:5] == "MACH0":
            self.filetype = "MACHO"
        elif self.filetype[:3] == "ELF":
            self.filetype = "ELF"
        elif self.filetype[:2] == "PE":
            self.filetype = "PE"

        # projects are quite broken at this time, so we will save this for
        # brighter days
        
        '''
        # load project, if no project already exists, analyze
        if useProjects:
            if projectName is None:
                projectName = self._getFileNameFromPath(path)
            prj = filter(lambda x: x == projectName, self.r.cmdj("Pj"))
            if len(prj) > 0:
                self.r.cmd("Po %s" % projectName)
            else:
                self.r.cmd("aaa")
                self._additionalAnalysis()
                self.r.cmd("Ps %s" % projectName)
        else:
            self.r.cmd("aaa")
            self._additionalAnalysis()
        
        '''
        self.r.cmd("aaa")
        self._additionalAnalysis()
        


    def _additionalAnalysis(self):
        # label j_ functions
        candidates = map(lambda x: x['offset'] ,filter(lambda y: y['nbbs'] == 1 and y['size'] <= 10, 
                         self.r.cmdj("aflj")))
        for candidate in candidates:
            try:
                if self._getBasicBlocks(candidate)[0]['ninstr'] == 1 and self.getMnem(candidate) == "jmp":
                    op = self._getOpndDict(candidate, 0)
                    if op['type'] == "imm" and ".dll_" in self.getName(op['value']):
                        self.setName(candidate, "j_" + self.normalizeFuncName(self.getName(op['value'])))
            except Exception as e:
                logging.debug("Exception searching for trampoline functions, candidate %s: %s" % (self.eh.hexString(candidate), str(e)))


    def _getFileNameFromPath(self, path):
        head, tail = ntpath.split(path)
        return tail or ntpath.basename(head)

    def getFuncStart(self, addr):
        try:
            return self.r.cmdj("afij %d" % addr)[0]['offset']
        except:
            return None

    def getFuncEnd(self, addr):
        try:
            fi = self.r.cmdj("afij %d" % addr)[0]
            return fi['offset'] + fi['size']
        except:
            return None

    def getFuncName(self, addr, normalized=True):
        if normalized:
            return self.normalizeFuncName(self.getName(self.getFuncStart(addr)))
        else:
            return self.getName(self.getFuncStart(addr))

    def getMnem(self, addr):
        try:
            return self.r.cmdj("aoj @%d" % addr)[0]['mnemonic']
        except:
            return ""

    def _getBasicBlocks(self, addr):
        return self.r.cmdj("afbj %d" % self.r.cmdj("afij %d" % addr)[0]['offset'])

    # for broken project file issue
    def _getBlockInsnCount(self, bb):
        try:
            if bb['ninstr'] == 0:
                cnt = 0
                addr = bb['addr']
                while addr < bb['addr'] + bb['size']:
                    insn = self.rcmdj("aoj 1 @%d" % addr)
                    addr += insn['size']
                    cnt += 1
                return cnt
            else:
                return bb['ninstr']
        except:
            return 0

    # gets address of last instruction in the basic block containing addr
    def getBlockEndInsnAddr(self, addr, flowchart):
        try:
            bbs = self._getBasicBlocks(addr)
            bb = filter(lambda x: x['addr'] <= addr and (x['addr'] + x['size']) > addr, bbs)[0]
            insnCount = self._getBlockInsnCount(bb)
            return self.r.cmdj("pdj %d @%d" % (insnCount, bb['addr']))[-1]['offset']
        except:
            return None

    def skipJumpTable(self, addr):
        pass

    def getMinimumAddr(self):
        if self.filetype != "PE":
            segmentCmd = self.r.cmdj("iSSj")
        else:
            segmentCmd = self.r.cmdj("iSj")
        return sorted(filter(lambda y: y > 0, map(lambda x: x['vaddr'], segmentCmd)))[0]

    def getMaximumAddr(self):
        if self.filetype != "PE":
            segmentCmd = self.r.cmdj("iSSj")
        else:
            segmentCmd = self.r.cmdj("iSj")
        maxAddr = 0
        for seg in segmentCmd:
            if seg['vaddr'] + seg['vsize'] > maxAddr:
                maxAddr = seg['vaddr'] + seg['vsize']
                
        return maxAddr

    def getBytes(self, addr, size):
        # prz and pr seem to have problems, maybe due to certain unprintable characters going over the pipe
        return binascii.unhexlify(self.r.cmd("p8 %d @%d" % (size, addr)).replace("\n", ""))

    def getCString(self, addr):
        buf = ""
        while (address >= self.getMinimumAddr() 
               and address < self.getMaximumAddr() 
               and self.getBytes(address, 1) != "\x00"):
            buf += self.getBytes(address, 1)
            address += 1
        return buf

    def getOperand(self, addr, opndNum):
        opndCnt = len(self.r.cmdj("aoj @%d" % addr)[0]['opex']['operands'])
        if opndNum > opndCnt - 1:
            return None
        opsString = " ".join(self.r.cmdj("aoj @%d" % addr)[0]['disasm'].split(" ")[1:])
        if opsString[0] == "{":
            opsString = opsString[1:-1]
        return opsString.split(", ")[opndNum]
        

    def getWordValue(self, addr):
        return self.r.cmdj("pv2j 1 @%d" % addr)['value']

    def getDwordValue(self, addr):
        return self.r.cmdj("pv4j 1 @%d" % addr)['value']

    def getQWordValue(self, addr):
        return self.r.cmdj("pv8j 1 @%d" % addr)['value']

    def isThumbMode(self, addr):
        return self.r.cmdj("afij @%d" % addr)[0]['bits'] == 16

    # gets name of smallest of segments containing addr, unless smallest is set to False
    def getSegmentName(self, addr, smallest=True):
        if self.filetype != "PE":
            segmentCmd = self.r.cmdj("iSSj")
        else:
            segmentCmd = self.r.cmdj("iSj")
        flt = lambda x: x['vaddr'] <= addr and (x['vaddr'] + x['vsize']) > addr
        try:
            if smallest:
                return min(filter(flt, segmentCmd), key = lambda x: x['vsize'])['name']
            else:
                return max(filter(flt, segmentCmd), key = lambda x: x['vsize'])['name']
        except:
            return ""

    def getSegmentStart(self, addr):
        if self.filetype != "PE":
            segmentCmd = self.r.cmdj("iSSj")
        else:
            segmentCmd = self.r.cmdj("iSj")
        flt = lambda x: x['vaddr'] <= addr and (x['vaddr'] + x['vsize']) > addr
        try:
            return filter(flt, segmentCmd)[0]['vaddr']
        except:
            return -1

    def getSegmentEnd(self, addr):
        if self.filetype != "PE":
            segmentCmd = self.r.cmdj("iSSj")
        else:
            segmentCmd = self.r.cmdj("iSj")
        flt = lambda x: x['vaddr'] <= addr and (x['vaddr'] + x['vsize']) > addr
        try:
            seg = filter(flt, segmentCmd)[0]
            return seg['vaddr'] + seg['vsize']
        except:
            return -1


    def getSegmentSize(self, addr):
        return self.getSegmentEnd(addr) - self.getSegmentStart(addr)
        
    # Radare2 fills in unknown bytes with null bytes
    def getSegmentDefinedSize(self, addr):
        return self.getSegmentSize(addr)

    def getSegments(self):
        if self.filetype != "PE":
            segmentCmd = self.r.cmdj("iSSj")
        else:
            segmentCmd = self.r.cmdj("iSj")
        return map(lambda x: x['vaddr'], segmentCmd)
            
    # if any of the section APIs fail, the address may still be a part of a segment
    def getSectionName(self, addr, smallest=True):
        flt = lambda x: x['vaddr'] <= addr and (x['vaddr'] + x['vsize']) > addr
        sections = filter(flt, self.r.cmdj("iSj"))
        if len(sections) > 0:
            if smallest:
                return min(sections, key = lambda x: x['vsize'])['name']
            else:
                return max(sections, key = lambda x: x['vsize'])['name']
        else:
            return self.getSegmentName(addr)
            

    def getSectionStart(self, addr):
        flt = lambda x: x['vaddr'] <= addr and (x['vaddr'] + x['vsize']) > addr
        sections = filter(flt, self.r.cmdj("iSj"))
        if len(sections) > 0:
            return sections[0]['vaddr']
        else:
            return self.getSegmentStart(addr)

    def getSectionEnd(self, addr):
        flt = lambda x: x['vaddr'] <= addr and (x['vaddr'] + x['vsize']) > addr
        sections = filter(flt, self.r.cmdj("iSj"))
        if len(sections) > 0:
            return sections[0]['vaddr'] + sections[0]['size']
        else:
            return self.getSegmentEnd(addr)

    def getSectionSize(self, addr):
        flt = lambda x: x['vaddr'] <= addr and (x['vaddr'] + x['vsize']) > addr
        sections = filter(flt, self.r.cmdj("iSj"))
        if len(sections) > 0:
            return sections[0]['size']
        else:
            return self.getSegmentSize(addr)

    def getSections(self):
        return map(lambda x: x['vaddr'], self.r.cmdj("iSj"))

    # gets disassembled instruction with names and comments as a string
    def getDisasmLine(self, addr):
        insn = self.r.cmdj("pdj 1 @%d" % addr)[0]
        if 'comment' in insn:
            return insn['disasm'] + " ; %s" % base64.b64decode(insn['comment'])
        else:
            return insn['disasm']

    def getName(self, addr):
        try:
            self.r.cmd("fs symbols")
            ret = filter(lambda x: x['offset'] == addr and 
                                   x['name'][:4] != "fcn." and 
                                   re.match(r"entry[\d]+$", x['name']) == None, 
                                   self.r.cmdj("fnj"))[0]['name']
        except:
            try:
                self.r.cmd("fs imports")
                ret = filter(lambda x: x['offset'] == addr and 
                                       x['name'][:4] != "fcn." and 
                                       re.match(r"entry[\d]+$", x['name']) == None, 
                                       self.r.cmdj("fnj"))[0]['name']
            except:
                try:
                    self.r.cmd("fs *")
                    ret = filter(lambda x: x['offset'] == addr and 
                                           x['name'][:4] != "fcn." and 
                                           re.match(r"entry[\d]+$", x['name']) == None, 
                                           self.r.cmdj("fnj"))[0]['name']
                except:
                    ret = ""
        self.r.cmd("fs *")
        return ret

    def getNameAddr(self, name):
        try:
            return filter(lambda x: x['name'].replace("\n", "") == name, self.r.cmdj("fnj"))[0]['offset']
        except:
            try:
                return filter(lambda x: self.normalizeFuncName(x['name'].replace("\n", ""))
                              == self.normalizeFuncName(name), self.r.cmdj("fnj"))[0]['offset']
            except:
                try:
                    return filter(lambda x: self.normalizeFuncName(x['name'].replace("\n", ""), True) 
                                  == self.normalizeFuncName(name, True), self.r.cmdj("fnj"))[0]['offset']
                except:
                    # if it's a hexadecimal number such as returned from getOpnd, convert it to an integer
                    if name[:2] == "0x":
                        return int(name, 16)
                    else:
                        return None 

    def _getOpndDict(self, addr, opndNum):
        opndCnt = len(self.r.cmdj("aoj @%d" % addr)[0]['opex']['operands'])
        if opndNum > opndCnt - 1:
            return None
        return self.r.cmdj("aoj @%d" % addr)[0]['opex']['operands'][opndNum]

    def getOpndType(self, addr, opndNum):
        mnem = self.getMnem(addr)
        opnd = self._getOpndDict(addr, opndNum)
        if opnd is None:
            return None
        if opnd['type'] == "reg":
            return self.o_reg
        elif opnd['type'] == "imm":
            if mnem == "call":
                return self.o_near
            else:
                return self.o_imm
        elif opnd['type'] == "mem":
            if "base" in opnd:
                if opnd['disp'] == 0:
                    return self.o_phrase
                else:
                    return self.o_displ
            elif opnd['disp'] != 0:
                return self.o_mem
                
        return None

    def getOpndValue(self, addr, opndNum):
        opnd = self._getOpndDict(addr, opndNum)
        if opnd is None:
            return None
        if opnd['type'] == "imm":
            return opnd['value']
        elif opnd['type'] == "mem":
            return opnd['disp']
        return None

    def makeInsn(self, addr):
        pass

    def createFunction(self, addr):
        pass

    def getFlowChart(self, addr):
        bbs = self._getBasicBlocks(addr)
        flowchart = []
        id = 0    
        for bb in bbs:
            flowchart.append(BasicBlock(flowchart, 
                                        id, 
                                        bb['addr'], 
                                        bb['size'], 
                                        bb.get('jump', -1), 
                                        bb.get('fail', -1)))
            id += 1
        return flowchart


    def getSpDelta(self, addr):
        return 0    

    def getXrefsTo(self, addr):
        return map(lambda x: x['from'], self.r.cmdj("axtj %d" % addr))

    def getArch(self):
        return self.arch

    def getBitness(self):
        return self.bitness

    def getFileType(self):
        return self.filetype

    def getInsnSize(self, addr):
        return self.r.cmdj("pdj 1 @%d" % addr)[0]['size']

    def isTerminatingBB(self, bb):
        if len(list(bb.succs())) == 0:
            return True
        return False

    def skipJumpTable(self, addr):
        # finds next block after the immediate next block which has the jump table in it
        try:
            return filter(lambda x: x['addr'] > address + 4, r.cmdj("afbj @%d" % address))[0]['addr']
        except:
            return addr

    def setName(self, addr, name, size=0):
        if self.getFuncStart(addr) == addr:
            if size == 0:
                size = self.getFuncEnd(addr) - self.getFuncStart(addr)

        if name[:4] != "sym.":
            name = "sym." + name

        self.r.cmd("fs symbols; f %s %d %d; fs *" % (name, size, addr))

    def setComment(self, addr, comment, repeatable=False):
        self.r.cmd("CCu base64:%s @%d" % (base64.b64encode(comment), addr))