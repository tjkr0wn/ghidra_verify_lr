from __main__ import currentProgram
from ghidra.util.datastruct import ByteArray
from ghidra.program.flatapi import FlatProgramAPI
from ghidra.program.model.symbol import SourceType
from ghidra.program.model.listing import FunctionManager
import ghidra.program.model.address.AddressSet as AddressSet
import ghidra.program.model.symbol.SourceType as SourceType
from ghidra.program.model.mem import MemBuffer as MemBuffer
from ghidra.program.model.mem import MemoryBlock as MemoryBlock
from ghidra.app.plugin.assembler.Assemblers import getAssembler as getAssembler
import ghidra.program.model.data.VoidDataType as VoidDataType
import ghidra.program.model.symbol.SourceType as SourceType
import ghidra.program.disassemble.Disassembler as Disassembler
from ghidra.program.disassemble import DisassemblerMessageListener as DisassemblerMessageListener
from ghidra.util.task import TaskMonitor as TaskMonitor

#Yeah, this class is kinda useless. Just kinda helps to keep things here.
class iBoot():
    def __init__(self):
        self.ibootbase = currentProgram.getImageBase()
        self.ibootmemory = currentProgram.getMemory()
        self.listing = currentProgram.getListing()
        self.asm = getAssembler(currentProgram)
