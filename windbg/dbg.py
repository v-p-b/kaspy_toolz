import pykd
import os
import sys

curr_info=pykd.dbgCommand("!process -1 0")

if curr_info.split(" ")[-1].strip() != "avp.exe":
    print "[+] Looking up AVP..."

    avp_info=pykd.dbgCommand("!process 0 0 avp.exe")
    avp_eprocess=avp_info.split(" ")[1]
    print("[+] Found EPROCESS: %s" % avp_eprocess)
    print("[+] Changing context...")
    pykd.dbgCommand(".process -r -i -p %s" % avp_eprocess)
    print("[+] Context changed")

print("[+] Currently in AVP!")
if len(sys.argv)>1 and sys.argv[1]=="switch":
    print("[+] My job is done.")
    exit()

print("[+] Setting BP struct check failure")
pykd.dbgCommand('bu prcore+0x12912')
print("[+] Setting packet monitor")
pykd.dbgCommand('bu prremote+0x1bb26 ".echo pkt:;dd ebx L20;g"')
print("[+] Setting BP on call")
pykd.dbgCommand('bu prremote+0x1d4f4')
