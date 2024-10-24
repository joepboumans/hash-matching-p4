import numpy as np
import math
import zlib
import struct

def crc32(src_addr, dst_addr, src_port, dst_port, protocol, init_val):
    src_val = b''
    for x in src_addr.split('.'):
        src_val += struct.pack("B", int(x))

    dst_val = b''
    for x in dst_addr.split('.'):
        dst_val += struct.pack("B", int(x))

    srcp_val = int(src_port).to_bytes(2, 'little')
    dstp_val = int(dst_port).to_bytes(2, 'little')
    protocol = struct.pack("B", int(protocol))
    bytes_string = src_val + dst_val + srcp_val + dstp_val + protocol
    # bytes_string = protocol + dstp_val + srcp_val + dst_val + src_val
    print(f"src addrs : {src_val.hex()}")
    print(f"dst addrs : {dst_val.hex()}")
    print(f"srcp  : {srcp_val.hex()}")
    print(f"dstp  : {dstp_val.hex()}")
    print(f"protocol  : {protocol.hex()}")
    print(bytes_string.hex())
    
    n = zlib.crc32(bytes_string)
    # n = n ^ 0xFFFFFFFF
    return n + (1<<32) if n < 0 else n
    

