from unicorn import *
from unicorn.x86_const import *
import binascii

import struct
import time

def hook_code(mu, address, size, user_data):
    print(">>> Tracing instruction at 0x%x, instruction size = %u ESI=%08x EDI=%08x  EBX=%08x" %(address, size, mu.reg_read(UC_X86_REG_ESI),mu.reg_read(UC_X86_REG_EDI),mu.reg_read(UC_X86_REG_EBX)))


class FNV_hash(object):
    def __init__(self):
        self.mu = Uc(UC_ARCH_X86, UC_MODE_32)
        
        self.code_hash = '379 BYTES HERE'.decode('hex') 
        self.code_loop = '87 BYTES HERE'.decode('hex') 
        self.code_multi = '52 BYTES HERE'.decode('hex') 
        self.code_calc = '70 BYTES HERE'.decode('hex') 

        self.code_nop="43434343".decode('hex')

        self.mu.mem_map(0x10009000L,0x4000)
        self.mu.mem_map(0x70fff000L,0x1000)
        self.mu.mem_map(0x10036000L,0x4000)
        self.mu.mem_map(0x20000000L,0x1000)

        self.mu.mem_write(0x100098e0L, self.code_hash)
        self.mu.mem_write(0x100096b0L, self.code_loop)
        self.mu.mem_write(0x10036e60L, self.code_multi)
        self.mu.mem_write(0x10009710L, self.code_calc)

    def set_preimage(self,pi):
        self.mu.mem_write(0x20000100L,pi)

    def get_preimage(self):
        return self.mu.mem_read(0x20000100L,len(self.preimage))


    def set_sid(self,sid0,sid1):
        self.mu.mem_write(0x20000108L,sid0)
        self.mu.mem_write(0x2000010CL,sid1)

    def set_key(self,key0,key1):
        self.mu.mem_write(0x20000100L,key0)
        self.mu.mem_write(0x20000104L,key1)

    def set_payload(self,payload,payload_len=None):
        self.payload=payload
        if payload_len==None:
            payload_len=len(payload)

        self.mu.mem_map(0x30000000L,0x2000)
        self.mu.mem_write(0x30000000L,payload)
        self.mu.mem_write(0x20000110L, (b"\x00"*64)+struct.pack("<i",0x30000000L)+struct.pack("<i",0x30000000L+payload_len))
        self.mu.mem_write(0x2000012cL, '01013200'.decode('hex'))

    def preimage_corrupt(self,n):
        x=self.mu.mem_read(0x20000100+n,1)
        self.mu.mem_write(0x20000100+n,chr(ord(x)^0xff))

    # orig\0x2b:0x2b+8 => preimage\0x46:0x46+8 < Turns out this is a timestamp...
    # must be called after set_payload... :P
    def set_msgid(self,id):
        self.mu.mem_write(0x20000100+0x46,id)

    def _start_unicorn(self, startaddr):
        try:
            #self.mu.hook_add(UC_HOOK_CODE, hook_code, {})
            self.mu.emu_start(startaddr, 0)
        except Exception as e:
            if self.mu.reg_read(UC_X86_REG_EIP) == 0x10009A3E:
                #print binascii.hexlify(self.mu.mem_read(0x20000100L,88))
                #print binascii.hexlify(self.mu.mem_read(0x30000000L,0x29))
                return (self.mu.reg_read(UC_X86_REG_EDX), self.mu.reg_read(UC_X86_REG_ESI))
            if self.mu.reg_read(UC_X86_REG_EIP) == 1:
                return
            else:
                print '[!] Exception occured - Emulator state (x86):'
                print "UC_X86_REG_EAX : %08X" % (self.mu.reg_read(UC_X86_REG_EAX))
                print "UC_X86_REG_EBP : %08X" % (self.mu.reg_read(UC_X86_REG_EBP))
                print "UC_X86_REG_EBX : %08X" % (self.mu.reg_read(UC_X86_REG_EBX))
                print "UC_X86_REG_ECX : %08X" % (self.mu.reg_read(UC_X86_REG_ECX))
                print "UC_X86_REG_EDI : %08X" % (self.mu.reg_read(UC_X86_REG_EDI))
                print "UC_X86_REG_EDX : %08X" % (self.mu.reg_read(UC_X86_REG_EDX))
                print "UC_X86_REG_ESI : %08X" % (self.mu.reg_read(UC_X86_REG_ESI))
                print "UC_X86_REG_ESP : %08X" % (self.mu.reg_read(UC_X86_REG_ESP))
                print "UC_X86_REG_EIP : %08X" % (self.mu.reg_read(UC_X86_REG_EIP))
                print "Stack:"
                esp=self.mu.reg_read(UC_X86_REG_ESP)
                ebp=self.mu.reg_read(UC_X86_REG_EBP)
                for sa in xrange(esp,0x70ffff10,4):
                    print "%08x : %s" % (sa,binascii.hexlify(self.mu.mem_read(sa,4)))
                raise e
    def run(self):
        self.mu.reg_write(UC_X86_REG_ESP, 0x70ffff00)
        self.mu.reg_write(UC_X86_REG_EBP, 0x70ffff00)
        self.mu.reg_write(UC_X86_REG_EAX, 0x20000100+24)
        self.mu.reg_write(UC_X86_REG_ECX, 0x20000100+8)
        self.mu.reg_write(UC_X86_REG_EDX, 0x20000100)
        self.mu.mem_write(0x70ffff04, struct.pack("<I",0x20000100+24))

        return self._start_unicorn(0x100098e0L)

if __name__ == "__main__":
    for i in xrange(0,176/2):
        print ">>>>>>>>>>> %d <<<<<<<<<<<<<<" % i
        fnv=FNV_hash()
        fnv.set_key("80B2A9C3".decode('hex'),'9C66BEAD'.decode('hex'))
        fnv.set_sid('3B78FAFF'.decode('hex'),'5187B602'.decode('hex'))
        fnv.set_payload("00000000000000001A000000010000000300000000000000E903080000002882F12700000000000000".decode('hex'))
        fnv.set_msgid('4390930853CCD301'.decode('hex'))
        fnv.preimage_corrupt(i)                 
        try:
            res_orig=fnv.run()
            print "%08X %08X" % (res_orig[0],res_orig[1])
        except:
            pass
        
        print "="*16

