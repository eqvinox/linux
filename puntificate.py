from socket import *
import selectors
import struct
from collections import namedtuple
import ctypes
import ctypes.util
from scapy.layers.l2 import Ether
import scapy.layers.inet
from scapy.layers.inet import (
    IP,
    IPerror,
    ICMP,
    ICMPExtension_Object,
    ICMPExtension_Header,
    ICMPExtension_InterfaceInformation,
)

SOCK_PUNT = 11
ETH_P_ALL = 3
ARPHRD_VOID = 0xFFFF
SOL_PACKET = 263
PACKET_PUNT_CONSUME = 25

_libc = ctypes.CDLL(ctypes.util.find_library("c"), use_errno=True)

_bind = _libc.bind
_bind.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_size_t]
_bind.restype = ctypes.c_int

_recvfrom = _libc.recvfrom
_recvfrom.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_size_t, ctypes.c_int, ctypes.c_char_p, ctypes.POINTER(ctypes.c_size_t)]
_recvfrom.restype = ctypes.c_ssize_t

sockaddr_punt = namedtuple("sockaddr_punt", [
    "spunt_family",
    "spunt_protocol",
    "spunt_ifindex",
    "spunt_hatype",
    "spunt_pkttype",
    "spunt_halen",
    "spunt_location",
    "spunt_info",
])

def mksockaddr(args: sockaddr_punt, include_info=False):
    if include_info:
        return struct.pack("@HHIHBB8s24s", *args)
    else:
        return struct.pack("@HHIHBB8s", *(args[:-1]))

def decsockaddr(raw: bytes, location_len=0):
    if location_len:
        return sockaddr_punt(*struct.unpack("@HHIHBB8s%ds" % location_len, raw))
    else:
        return sockaddr_punt(*(struct.unpack("@HHIHBB8s", raw) + (b"",)))

def sockaddr_for_bind():
    spunt = sockaddr_punt(
        AF_PACKET,
        htons(ETH_P_ALL),
        0,
        ARPHRD_VOID,
        0,
        8,
        b"ipv4ttl0",
        b"",
    )
    return mksockaddr(spunt)

sock = socket(AF_PACKET, SOCK_PUNT, 0)
sock.setblocking(False)
sock.setsockopt(SOL_PACKET, PACKET_PUNT_CONSUME, 1)

spunt = sockaddr_for_bind()
assert _bind(sock.fileno(), spunt, len(spunt)) == 0

reply_sock = socket(AF_PACKET, SOCK_RAW, 0)
reply_sock.setblocking(False)

class ICMPExtension_MPLSInformation(ICMPExtension_Object):
    from scapy.fields import ShortField, ByteEnumField, ByteField, BitField

    name = "ICMP Extension Object - MPLS (RFC4950)"
    fields_desc = [
        ShortField("len", None),
        ByteEnumField("classnum", 1, scapy.layers.inet._ICMP_classnums),
        ByteField("classtype", 1),
        BitField("label", None, 20),
        BitField("exp", None, 3),
        BitField("bos", 1, 1),
        BitField("ttl", 0, 8),
    ]


def rx_handler():
    addr = ctypes.create_string_buffer(64)
    addrlen = ctypes.c_size_t(64)
    pktraw = ctypes.create_string_buffer(16384)
    ret = _recvfrom(sock.fileno(), pktraw, 16384, 0, addr, ctypes.pointer(addrlen))
    assert ret > 0

    pkt = Ether(pktraw[:ret])
    addr = decsockaddr(addr[:addrlen.value], 4)

    oif_index, = struct.unpack("@I", addr.spunt_info)

    iif = if_indextoname(addr.spunt_ifindex)
    oif = if_indextoname(oif_index)
    print(f"{addr!r} ({iif}->{oif}) => {pkt!r}")

    pkt.show()
    pkt_ip = pkt.getlayer(IP)
    
    einfo = ICMPExtension_InterfaceInformation(
        has_ifindex=1,
        has_ipaddr=0,
        has_ifname=1,
        ifindex=addr.spunt_ifindex,
        ifname=iif,
    )

    einfo = ICMPExtension_MPLSInformation(
        label = 31337,
    )

    reply = Ether(src=pkt.dst, dst=pkt.src)
    reply /= IP(dst=pkt_ip.src, src="192.0.0.8")
    reply /= ICMP(type=11, code=0, ext=ICMPExtension_Header() / einfo)
    reply /= IPerror(bytes(pkt_ip)[:128])

    #reply.show2()
    reply_sock.sendto(bytes(reply), (iif, 0))

sel = selectors.DefaultSelector()
sel.register(sock, selectors.EVENT_READ, rx_handler)
print("running")

while evts := sel.select():
    for key, _ in evts:
        key.data()
