import random
import socket
import sys

from scapy.all import IP, TCP, send, sr1

__author__ = 'bennettaur'



"""
Very low level network sniffer without scapy: http://www.binarytides.com/python-packet-sniffer-code-linux/

TCP syn retries: http://man7.org/linux/man-pages/man7/tcp.7.html search tcp_syn_retries

TCP Keepalives: https://utcc.utoronto.ca/~cks/space/blog/python/TcpKeepalivesInPython
"""

def scapy_tcp_conn():
    # VARIABLES
    src = sys.argv[1]
    dst = sys.argv[2]
    sport = random.randint(1024,65535)
    dport = int(sys.argv[3])

    # SYN
    ip=IP(src=src,dst=dst)
    SYN=TCP(sport=sport,dport=dport,flags='S',seq=1000)
    SYNACK=sr1(ip/SYN)

    # ACK
    ACK=TCP(sport=sport, dport=dport, flags='A', seq=SYNACK.ack, ack=SYNACK.seq + 1)
    send(ip/ACK)


def tcp_keepalive():
    s = socket.socket()
    s.connect(('192.168.2.109', 55555))
    s.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
    s.connect(('192.168.2.109', 55555))

    # TCP keepalive options are: TCP_KEEPIDLE, TCP_KEEPINTVL, and TCP_KEEPCNT
    # On linux the idle time is set using socket.TCP_KEEPIDLE. On OS X this value is missing in python but is still
    # defined in the TCP stack as 0x10

    TCP_KEEPIDLE = 0x10
    s.setsockopt(socket.IPPROTO_TCP, TCP_KEEPIDLE, 1)
    s.setsockopt(socket.IPPROTO_TCP, TCP_KEEPIDLE, 100)

