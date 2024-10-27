import base64
import binascii
import json
import logging
import ntpath
import re
import struct
import flare_emu
import rzpipe


class BasicBlock:

  def __init__(self, flowchart, id, addr, size, jump, fail):
    self.start_ea = addr
    self.size = size
    self.end_ea = addr + size
    self.successors = [fail, jump]
    self.type = -1
    self.id = id
    self.flowchart = flowchart

  def succs(self):
    for z in list(
        map(
            lambda x: self.getBlockByAddr(x),
            list(filter(lambda y: y != -1, self.successors)),
        )
    ):
      yield z

  def getBlockByAddr(self, addr):
    for bb in self.flowchart:
      if addr >= bb.start_ea and addr < bb.end_ea:
        return bb


# in order to minimize rzpipe overhead, we will cache things
class RizinAnalysisHelper(flare_emu.AnalysisHelper):

  def __init__(self, path, eh):
    self.cache = {}
    super(RizinAnalysisHelper, self).__init__()
    try:
      self.eh = eh
      self.r = rzpipe.open(path)
      self.path = path
    except Exception as e:
      print('error loading %s in Rizin: %s' % (path, str(e)))
      exit(1)

    info = self.r.cmdj('iAj')
    self.arch = info[0]['arch'].upper()
    self.bitness = info[0]['bits']
    self.filetype = self.r.cmdj('ij')['core']['format'].upper()

    if self.filetype[:5] == 'MACH0':
      self.filetype = 'MACHO'
    elif self.filetype[:3] == 'ELF':
      self.filetype = 'ELF'
    elif self.filetype[:2] == 'PE':
      self.filetype = 'PE'

    self.r.cmd('aaa')

    # initialize cache
    self.clearCache()

    self._additionalAnalysis()

  def _additionalAnalysis(self):
    # label j_ functions
    candidates = list(
        map(
            lambda x: x['offset'],
            list(
                filter(
                    lambda y: y['nbbs'] == 1 and y['size'] <= 10,
                    self.r.cmdj('aflj'),
                )
            ),
        )
    )
    for candidate in candidates:
      try:
        if (
            self._getBasicBlocks(candidate)[0]['ninstr'] == 1
            and self.getMnem(candidate) == 'jmp'
        ):
          op = self._getOpndDict(candidate, 0)
          if op['type'] == 'imm' and '.dll_' in self.getName(op['value']):
            self.setName(
                candidate,
                'j_' + self.normalizeFuncName(self.getName(op['value'])),
            )
      except Exception as e:
        self.eh.logger.debug(
            'Exception searching for trampoline functions, candidate %s: %s'
            % (self.eh.hexString(candidate), str(e))
        )

  def _getFileNameFromPath(self, path):
    head, tail = ntpath.split(path)
    return tail or ntpath.basename(head)

  def _getBasicBlocks(self, addr):
    addr = self.getFuncStart(addr)  # caches blocks for this function
    return self.cache['afb'][addr]

  def _getFuncInsns(self, funcAddr):
    # pdfj does not return expected results
    function = self.r.cmdj(f'pdfj @ {funcAddr}')
    if 'ops' in function:
      return function['ops']
    return []

  # cache instructions, blocks, and opcodes for a function
  def _cacheFunc(self, funcAddr):
    insns = self._getFuncInsns(funcAddr)
    cachedInsns = list(map(lambda x: x['offset'], self.cache['pd']))
    self.cache['pd'] += list(
        filter(lambda x: x['offset'] not in cachedInsns, insns)
    )

    ops = self.r.cmdj(f'aoj {len(insns)} @ {funcAddr}')
    cachedOps = list(map(lambda x: x['addr'], self.cache['ao']))
    self.cache['ao'] += list(filter(lambda x: x['addr'] not in cachedOps, ops))
    self.cache['afb'][funcAddr] = self.r.cmdj(f'afbj @ {funcAddr}')

  def _getOpcode(self, addr):
    op = list(filter(lambda x: x['addr'] == addr, self.cache['ao']))
    if len(op) > 0:
      return op[0]
    op = self.r.cmdj(f'aoj 1 @ {addr}')[0]
    self.cache['ao'].append(op)
    return op

  def _getInsn(self, addr):
    insn = list(filter(lambda x: x['offset'] == addr, self.cache['pd']))
    if len(insn) > 0:
      return insn[0]
    insn = self.r.cmdj(f'pdj 1 @ {addr}')[0]
    self.cache['pd'].append(insn)
    return insn

  def _deleteCacheItem(self, item):
    if isinstance(self.cache[item], list):
      self.cache[item] = []
    else:
      self.cache[item] = {}

  def _getFuncInfo(self, addr):
    try:
      if addr in self.cache['afi']:
        return self.cache['afi'][addr]

      afij = self.r.cmdj(f'afij @ {addr}')[0]
      self.cache['afi'][addr] = afij
      return self.cache['afi'][addr]
    except Exception as e:
      self.eh.logger.debug(
          'exception finding function info for %s: %s'
          % (self.eh.hexString(addr), str(e))
      )
      self.cache['afi'][addr] = None
      return None

  def clearCache(self, item=None):
    if item is None:
      self.cache = {}

      # symbols
      self.cache['fn'] = {}
      self.cache['fn']['symbols'] = self.r.cmdj('fs symbols;flj')
      self.cache['fn']['imports'] = self.r.cmdj('fs imports;flj')
      self.r.cmd('fs *')
      self.cache['fn']['all'] = self.r.cmdj('flj')

      # segments and sections
      if self.filetype != 'PE':
        self.cache['segments'] = self.r.cmdj('iSSj')
        self.cache['sections'] = self.r.cmdj('iSj')
      else:
        self.cache['segments'] = self.r.cmdj('iSj')
        self.cache['sections'] = self.cache['segments']

      # cached on demand
      self.cache['afi'] = {}  # function info keyed on requested addr
      self.cache['afb'] = {}  # basic blocks keyed on function addr
      self.cache['ao'] = []  # opcodes
      self.cache['pd'] = []  # instructions
      self.cache['funcs'] = []  # track cached functions
    elif item in self.cache:
      self._deleteCacheItem(item)

  # assume emulation for this function and cache everything
  def getFuncStart(self, addr):
    fi = self._getFuncInfo(addr)
    if fi == None:
      return None
    funcStart = fi['offset']
    if funcStart not in self.cache['funcs']:
      self.cache['funcs'].append(funcStart)
      self._cacheFunc(funcStart)
    return funcStart

  def getFuncEnd(self, addr):
    fi = self._getFuncInfo(addr)
    return fi['offset'] + fi['size']

  def getFuncName(self, addr, normalized=True):
    if normalized:
      return self.normalizeFuncName(self.getName(self.getFuncStart(addr)))
    else:
      return self.getName(self.getFuncStart(addr))

  def getMnem(self, addr):
    try:
      op = self._getOpcode(addr)
      return op['mnemonic']
    except:
      return ''

  # gets address of last instruction in the basic block containing addr
  def getBlockEndInsnAddr(self, addr, flowchart):
    try:
      bbs = self._getBasicBlocks(addr)
      bb = list(
          filter(
              lambda x: x['addr'] <= addr and (x['addr'] + x['size']) > addr,
              bbs,
          )
      )[0]
      addr = bb['addr']
      while addr < bb['addr'] + bb['size']:
        insn = self._getOpcode(addr)
        addr += insn['size']
      return insn['addr']
    except:
      return None

  def skipJumpTable(self, addr):
    pass

  def getMinimumAddr(self):
    # we don't want to consider PAGEZERO
    if self.filetype == 'MACHO':
      return sorted(
          list(
              filter(
                  lambda y: y > 0,
                  list(map(lambda x: x['vaddr'], self.cache['segments'])),
              )
          )
      )[0]
    else:
      return sorted(list(map(lambda x: x['vaddr'], self.cache['segments'])))[0]

  def getMaximumAddr(self):
    maxAddr = 0
    for seg in self.cache['segments']:
      if seg['vaddr'] + seg['vsize'] > maxAddr:
        maxAddr = seg['vaddr'] + seg['vsize']

    return maxAddr

  def getBytes(self, addr, size):
    # prz and pr seem to have problems, maybe due to certain unprintable characters going over the pipe
    return binascii.unhexlify(
        self.r.cmd(f'p8 {size} @ {addr}').replace('\n', '')
    )

  def getCString(self, addr):
    buf = ''
    while (
        address >= self.getMinimumAddr()
        and address < self.getMaximumAddr()
        and self.getBytes(address, 1) != '\x00'
    ):
      buf += self.getBytes(address, 1)
      address += 1
    return buf

  def getOperand(self, addr, opndNum):
    opndCnt = len(self._getOpcode(addr)['opex']['operands'])
    if opndNum > opndCnt - 1:
      return None
    opsString = ' '.join(self._getOpcode(addr)['disasm'].split(' ')[1:])
    if opsString[0] == '{':
      opsString = opsString[1:-1]
    return opsString.split(', ')[opndNum]

  def getWordValue(self, addr):
    return self.r.cmdj(f'pv2j 1 @ {addr}')['value']

  def getDwordValue(self, addr):
    return self.r.cmdj(f'pv4j 1 @ {addr}')['value']

  def getQWordValue(self, addr):
    return self.r.cmdj(f'pv8j 1 @ {addr}')['value']

  def isThumbMode(self, addr):
    return self.r.cmdj(f'afij @ {addr}')[0]['bits'] == 16

  # gets name of smallest of segments containing addr, unless smallest is set to False
  def getSegmentName(self, addr, smallest=True):
    flt = lambda x: x['vaddr'] <= addr and (x['vaddr'] + x['vsize']) > addr
    try:
      if smallest:
        return min(
            list(filter(flt, self.cache['segments'])), key=lambda x: x['vsize']
        )['name']
      else:
        return max(
            list(filter(flt, self.cache['segments'])), key=lambda x: x['vsize']
        )['name']
    except:
      return ''

  def getSegmentStart(self, addr):
    flt = lambda x: x['vaddr'] <= addr and (x['vaddr'] + x['vsize']) > addr
    try:
      return list(filter(flt, self.cache['segments']))[0]['vaddr']
    except:
      return -1

  def getSegmentEnd(self, addr):
    flt = lambda x: x['vaddr'] <= addr and (x['vaddr'] + x['vsize']) > addr
    try:
      seg = list(filter(flt, self.cache['segments']))[0]
      return seg['vaddr'] + seg['vsize']
    except:
      return -1

  def getSegmentSize(self, addr):
    return self.getSegmentEnd(addr) - self.getSegmentStart(addr)

  # Rizin fills in unknown bytes with null bytes
  def getSegmentDefinedSize(self, addr):
    return self.getSegmentSize(addr)

  def getSegments(self):
    return list(map(lambda x: x['vaddr'], self.cache['segments']))

  # if any of the section APIs fail, the address may still be a part of a segment
  def getSectionName(self, addr, smallest=True):
    flt = lambda x: x['vaddr'] <= addr and (x['vaddr'] + x['vsize']) > addr
    sections = list(filter(flt, self.cache['sections']))
    if len(sections) > 0:
      if smallest:
        return min(sections, key=lambda x: x['vsize'])['name']
      else:
        return max(sections, key=lambda x: x['vsize'])['name']
    else:
      return self.getSegmentName(addr)

  def getSectionStart(self, addr):
    flt = lambda x: x['vaddr'] <= addr and (x['vaddr'] + x['vsize']) > addr
    sections = list(filter(flt, self.cache['sections']))
    if len(sections) > 0:
      return sections[0]['vaddr']
    else:
      return self.getSegmentStart(addr)

  def getSectionEnd(self, addr):
    flt = lambda x: x['vaddr'] <= addr and (x['vaddr'] + x['vsize']) > addr
    sections = list(filter(flt, self.cache['sections']))
    if len(sections) > 0:
      return sections[0]['vaddr'] + sections[0]['size']
    else:
      return self.getSegmentEnd(addr)

  def getSectionSize(self, addr):
    flt = lambda x: x['vaddr'] <= addr and (x['vaddr'] + x['vsize']) > addr
    sections = list(filter(flt, self.cache['sections']))
    if len(sections) > 0:
      return sections[0]['size']
    else:
      return self.getSegmentSize(addr)

  def getSections(self):
    return list(map(lambda x: x['vaddr'], self.cache['sections']))

  # gets disassembled instruction with names and comments as a string
  def getDisasmLine(self, addr):
    insn = self._getInsn(addr)
    # invalid instruction bug
    if 'disasm' in insn and 'comment' in insn:
      return insn['disasm'] + ' ; %s' % base64.b64decode(insn['comment'])
    elif 'disasm' in insn:
      return insn['disasm']
    else:
      return '<error retrieving insn>'

  def getName(self, addr):
    try:
      ret = list(
          filter(
              lambda x: x['offset'] == addr
              and x['name'][:4] != 'fcn.'
              and re.match(r'entry[\d]+$', x['name']) == None,
              self.cache['fn']['symbols'],
          )
      )[0]['name']
    except:
      try:
        ret = list(
            filter(
                lambda x: x['offset'] == addr
                and x['name'][:4] != 'fcn.'
                and re.match(r'entry[\d]+$', x['name']) == None,
                self.cache['fn']['imports'],
            )
        )[0]['name']
      except:
        try:
          ret = list(
              filter(
                  lambda x: x['offset'] == addr
                  and x['name'][:4] != 'fcn.'
                  and re.match(r'entry[\d]+$', x['name']) == None,
                  self.cache['fn']['all'],
              )
          )[0]['name']
        except:
          try:
            ret = filter(
                lambda x: x['offset'] == addr
                and re.match(r'entry[\d]+$', x['name']) == None,
                self.cache['fn']['all'],
            )[0]['name']
          except:
            ret = ''
    return ret

  def getNameAddr(self, name):
    try:
      return list(
          filter(
              lambda x: x['name'].replace('\n', '') == name,
              self.cache['fn']['all'],
          )
      )[0]['offset']
    except:
      try:
        return list(
            filter(
                lambda x: self.normalizeFuncName(x['name'].replace('\n', ''))
                == self.normalizeFuncName(name),
                self.cache['fn']['all'],
            )
        )[0]['offset']
      except:
        # if it's a hexadecimal number such as returned from getOpnd, convert it to an integer
        if name[:2] == '0x':
          return int(name, 16)
        else:
          self.eh.logger.debug('error in getNameAddr')
          return None

  def _getOpndDict(self, addr, opndNum):
    opndCnt = len(self._getOpcode(addr)['opex']['operands'])
    if opndNum > opndCnt - 1:
      return None
    return self._getOpcode(addr)['opex']['operands'][opndNum]

  def getOpndType(self, addr, opndNum):
    mnem = self.getMnem(addr)
    opnd = self._getOpndDict(addr, opndNum)
    if opnd is None:
      return None
    if opnd['type'] == 'reg':
      return self.o_reg
    elif opnd['type'] == 'imm':
      if mnem == 'call':
        return self.o_near
      else:
        return self.o_imm
    elif opnd['type'] == 'mem':
      if 'base' in opnd:
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
    if opnd['type'] == 'imm':
      return opnd['value']
    elif opnd['type'] == 'mem':
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
      flowchart.append(
          BasicBlock(
              flowchart,
              id,
              bb['addr'],
              bb['size'],
              bb.get('jump', -1),
              bb.get('fail', -1),
          )
      )
      id += 1
    return flowchart

  def getSpDelta(self, addr):
    return 0

  def getXrefsTo(self, addr):
    xrefs = self.r.cmdj(f'axtj @ {addr}')
    to = []
    for el in xrefs:
      to.append(el['from'])

    return to

  def getArch(self):
    return self.arch

  def getBitness(self):
    return self.bitness

  def getFileType(self):
    return self.filetype

  def getInsnSize(self, addr):
    return self._getInsn(addr)['size']

  def isTerminatingBB(self, bb):
    if len(list(bb.succs())) == 0:
      return True
    return False

  def skipJumpTable(self, addr):
    # finds next block after the immediate next block which has the jump table in it
    try:
      return list(
          filter(lambda x: x['addr'] > addr + 4, self._getBasicBlocks(addr))
      )[0]['addr']
    except:
      return addr

  def setName(self, addr, name, size=0):
    if self.getFuncStart(addr) == addr:
      if size == 0:
        size = self.getFuncEnd(addr) - self.getFuncStart(addr)

    if name[:4] != 'sym.':
      name = 'sym.' + name

    self.r.cmd(f'fs symbols;f+ {name} @ {addr} {size}')
    self.cache['fn']['symbols'] = self.r.cmdj('fs symbols;flj')
    self.r.cmd('fs *')
    all_results = self.r.cmdj('flj')
    self.cache['fn']['all'] = all_results

  def setComment(self, addr, comment, repeatable=False):
    self.r.cmd(f'CCu base64:{base64.b64encode(comment)} @ {addr}')

  def normalizeFuncName(self, funcName):
    # remove Rizin's flag space prefixes
    if funcName[:4] == 'sym.':
      funcName = funcName[4:]

    if funcName[:4] == 'imp.':
      funcName = funcName[4:]

    if funcName[:5] == 'func.':
      funcName = funcName[5:]

    if funcName[:4] == 'fcn.':
      funcName = funcName[4:]

    if funcName[:4] == 'sub.':
      funcName = funcName[4:]

    # remove Rizin's library prefix
    funcName = re.sub(r'[A-Za-z0-9_]+\.dll_', '', funcName)

    return funcName
