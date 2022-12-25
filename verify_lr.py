# NOP VERIFY_LR operations
#@category iOS.iBoot

# ghidra_verify_lr
# Ghidra plugin for outlined x30 verification
# @tjkr0wn - Tarek Joumaa

from image import *

iboot = iBoot()

def main():
    """
    eor  x16,x30,x30, LSL #0x1                                                                                d0 07 1e ca
    tbz  x16,#0x3e, LAB_XXX                                                                                        50 00 f0 b6
    brk  #0xc471                                                                                              20 8e 38 d4
    """
    onlynop = False
    confirm = askString("Confirmation", "[-] WARNING: This tool patches some instructions in your Ghidra database. Continue? (Y/N)")
    if confirm != "Y":
        return
    confirm = askString("Confirmation", "[-] Would you like to create a stub for VERIFY_LR operations (1) or JUST nop them out? (2)")
    vls = find_verify_lr_sequences()
    if confirm != "2":
        create_verify_lr_stub(vls)
    else:
        onlynop = True
    patch_verify_lr_sequences(vls, onlynop)


def patch_verify_lr_sequences(vls, onlynop):
    print("[-] Patching...")
    for instruction in vls:
        for i in range(0, 3):
            opcode = "nop\n"
            if i == 2:
                if not onlynop:
                    opcode = "bl VERIFY_LR_STUB\n"
            iboot.asm.assemble(instruction.getInstructionContext().getAddress(), opcode)
            instruction = instruction.getNext()
        iboot.listing.setComment(instruction.getAddress().subtract(12), 1, "VERIFY_LR SEQUENCE NOP'ED HERE")
    print("[+] Patched!")


def create_verify_lr_stub(vls):
    """
    Let's find the boot trampoline and create
    this routine there. There's usually unused bytes on the same
    page that the boot trampoline is on, so that can be abused.
    (Does Ghidra allow a ghost function? That would be better than sticking it somewhere)
    """
    print("[-] Creating stub...")
    #For some odd reason, the Java iterator deletes itself after...a loop?
    #so I have to get the instruction iterator again.
    routine_addr = None
    for ins in iboot.listing.getInstructions(iboot.ibootbase, True):
        if ins.getRegister(0) == None:
            continue
        if ins.getMnemonicString() != "mov" or ins.getRegister(0).getName() != "x18":
            continue
        print("[+] Found 'mov x18, #0x0' @ {}".format(ins.getAddress()))
        """
        Ghidra will sometimes miss the NOPs and they won't be disassembled. This happens because
        it ignores all bytes after the 'wfe' loop. I just work around this by force disassembling
        bytes past the 'wfe'. I could match against the raw bytes, but it doesn't hurt to disassemble
        the NOPs anyways.
        """
        searchlimit = 80 #Should never go 80 instructions
        while searchlimit != 0:
            ins = ins.getNext()
            searchlimit -= 1
            if ins.getMnemonicString() == "wfe":
                break

        if searchlimit == 0:
            print("[!] Couldn't find WFE!")
            quit(0x42)

        Disassembler.getDisassembler(currentProgram, TaskMonitor.DUMMY, None).disassemble(ins.getAddress().add(8), AddressSet(ins.getAddress().add(8), ins.getAddress().add(10)))

        while ins.getMnemonicString() != "nop":
            ins = ins.getNext()
        print("[+] First NOP @ {}".format(ins.getAddress()))
        routine_addr = ins.getAddress()
        break
    if routine_addr == None:
        print("[!] Couldn't find boot trampoline or NOP's")
        quit(0x41)

    #I was gonna write the original instructions to here, but that's not really needed
    #when you think about it.
    stub = iboot.listing.createFunction("VERIFY_LR_STUB", routine_addr, AddressSet(routine_addr, routine_addr.add(4)), SourceType.USER_DEFINED)
    stub.setComment("VERIFY_LR_STUB: A stub'ed function for sequences ensuring x30 hasn't been tampered with. This eliminates the sequence, cleaning decompilation.")
    stub.setReturnType(VoidDataType().VOID, SourceType.DEFAULT)
    iboot.asm.assemble(routine_addr, "ret\n")
    print("[+] Created stub!")
    return routine_addr

def find_verify_lr_sequences():
        print("[+] Searching for EOR instructions")

        vls = []
        for ins in iboot.listing.getInstructions(iboot.ibootbase, True):
            #Ugly, but it works
            if ins.getMnemonicString() != "eor":
                continue
            if ins.getNext().getMnemonicString() != "tbz":
                continue
            if ins.getNext().getNext().getMnemonicString() != "brk":
                continue
            vls.append(ins)

        print("[+] Found {} VERIFY_LR sequences".format(len(vls)))
        return vls

if __name__ == "__main__":
    main()
