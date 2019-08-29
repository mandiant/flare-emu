import r2pipe
import binascii
import struct
import flare_emu
import re
import ntpath
import base64

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
    def __init__(self, path):
        super(Radare2AnalysisHelper, self).__init__()
        try:
            self.r = r2pipe.open(path)
            self.path = path
        except:
            print("error loading %s in radare2" % path)
            exit(1)

        # we have to gather all "i" related command info before loading project
        # because loading a project loses the binary and loading the binary
        # loses the project

        self.minimumAddr = sorted(map(lambda x: x['vaddr'], self.r.cmdj("iSj")))[0]
        sect = list(reversed(sorted(map(lambda x: (x['vaddr'], x['vsize']), self.r.cmdj("iSj")))))[0]
        self.maximumAddr = sect[0] + sect[1]
        info = self.r.cmdj("iAj")
        self.arch = info['bins'][0]['arch'].upper()
        self.bitness = info['bins'][0]['bits']
        self.filetype = self.r.cmdj("ij")['core']['format'].upper()
        if self.filetype[:5] == "MACH0":
            self.filetype = "MACHO"
        elif self.filetype[:3] == "ELF":
            self.filetype = "ELF"

        # backup segment info in case of project fail
        self.segInfo = self.r.cmdj("iSj")
        self.segments = map(lambda x: x['vaddr'], self.segInfo)

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
        candidates = map(lambda x: x['offset'] ,filter(lambda y: y['nbbs'] == 1 and y['size'] <= 10, self.r.cmdj("aflj")))
        for candidate in candidates:
            if self._getBasicBlocks(candidate)[0]['ninstr'] == 1 and self.getMnem(candidate) == "jmp":
                op = self._getOpndDict(candidate, 0)
                if op['type'] == "imm" and ".dll_" in self.getName(op['value']):
                    self.setName(candidate, "j_" + self.normalizeFuncName(self.getName(op['value'])))


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

    def getFuncName(self, addr):
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

    def getMininumAddr(self):
        return self.minimumAddr

    def getMaximumAddr(self):
        return self.maximumAddr

    def getBytes(self, addr, size):
        # prz and pr seem to have problems, maybe due to certain unprintable characters going over the pipe
        return binascii.unhexlify(self.r.cmd("p8 %d @%d" % (size, addr)).replace("\n", ""))

    def getCString(self, addr):
        buf = ""
        while address >= self.getMininumAddr() and address < self.getMaximumAddr() and self.getBytes(address, 1) != "\x00":
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
        pass

    def getDwordValue(self, addr):
        pass

    def getQWordValue(self, addr):
        pass

    def isThumbMode(self, addr):
        return self.r.cmdj("afij @%d" % addr)[0]['bits'] == 16

    def getSegName(self, addr):
        try:
            return filter(lambda x: x['vaddr'] <= addr and (x['vaddr'] + x['vsize']) > addr, self.r.cmdj("iSj"))[0]['name']
        except:
            # project issues
            return filter(lambda x: x['vaddr'] <= addr and (x['vaddr'] + x['vsize']) > addr, self.segInfo)[0]['name']

    def getSegStart(self, addr):
        try:
            return filter(lambda x: x['vaddr'] <= addr and (x['vaddr'] + x['vsize']) > addr, self.r.cmdj("iSj"))[0]['vaddr']
        except:
            return filter(lambda x: x['vaddr'] <= addr and (x['vaddr'] + x['vsize']) > addr, self.segInfo)[0]['vaddr']

    def getSegEnd(self, addr):
        try:
            seg = filter(lambda x: x['vaddr'] <= addr and (x['vaddr'] + x['vsize']) > addr, self.r.cmdj("iSj"))[0]
            return seg['vaddr'] + seg['vsize']
        except:
            seg = filter(lambda x: x['vaddr'] <= addr and (x['vaddr'] + x['vsize']) > addr, self.segInfo)[0]
            return seg['vaddr'] + seg['vsize']

    def getSegSize(self, addr, segEnd):
        # Radare2 fills in unknown bytes with null bytes
        return segEnd - addr

    def getSegments(self):
        try:
            return map(lambda x: x['vaddr'], self.r.cmdj("iSj"))
        except:
            return self.segments

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
        # size = self.r.cmdj("pdj 1 @%d" % addr)[0]['size']
        # self.r.cmd("C- %d @%d" % (size, addr))
        pass

    def createFunction(self, addr):
        pass

    def getFlowChart(self, addr):
        bbs = self._getBasicBlocks(addr)
        flowchart = []
        id = 0    
        for bb in bbs:
            flowchart.append(BasicBlock(flowchart, id, bb['addr'], bb['size'], bb.get('jump', -1), bb.get('fail', -1)))
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
        self.r.cmd("CCu base64:%s @%d" % (base64.b64decode(comment), addr))
