import random

from scapy.all import IP, TCP

from utils.layer3 import Layer3Socket
from utils.sniffer import TCPDumpSniffer

from tornado.tcpserver import TCPServer

__author__ = 'bennettaur'


class FakeOpenServer(TCPServer):

    def listen(self, port, address=""):
        super(FakeOpenServer, self).listen(port, address=address)
        self.real_open_port = port
        # Turn on open port faking
        filter = "tcp and not port {}".format(port)
        if address != "":
            filter += " and dst host {}".format(address)

        self.real_port_sniffer = TCPDumpSniffer(prn=self.fake_open_ports, filter=filter)
        self.sending_socket = Layer3Socket()

    def fake_open_ports(self, packet):
        tcp_packet = packet.payload

        flags = tcp_packet.sprintf("%TCP.flags%")

        if "S" not in flags or "S" != flags:
            return

        sequence_number = random.randint(0, 65535)
        ack_number = tcp_packet.seq + 1

        # This can also be done using packet.payload.dport
        source_port = tcp_packet.dport
        destination_port = tcp_packet.sport

        source_ip = packet.dst
        destination_ip = packet.src

        reply_packet = (IP(src=source_ip, dst=destination_ip) /
                  TCP(sport=source_port, dport=destination_port, seq=sequence_number, ack=ack_number, flags="SA"))

        self.sending_socket.send(reply_packet)

    def handle_data(self, data):
        pass

    def handle_stream(self, stream, address):
        stream.read_until_close(streaming_callback=self.handle_data)
