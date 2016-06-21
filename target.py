import pdb
import random

from scapy.all import Ether, IP, TCP

from utils.layer3 import Layer3Socket
from utils.misc import setup_logging
from utils.sniffer import TCPDumpSniffer

from tornado.ioloop import IOLoop
from tornado.tcpserver import TCPServer

__author__ = 'bennettaur'
logger = setup_logging(__name__)


class FakeOpenServer(TCPServer):

    def listen(self, port, address="", portrange=10):
        super(FakeOpenServer, self).listen(port, address=address)
        self.real_open_port = port
        # Turn on open port faking
        lower_range = port - portrange
        upper_range = port + portrange
        filter = "tcp and portrange {}-{}".format(lower_range, upper_range)

        self.real_port_sniffer = TCPDumpSniffer(prn=self.fake_open_ports, filter=filter)
        self.real_port_sniffer.start()
        self.sending_socket = Layer3Socket()

    def fake_open_ports(self, packet):
        if isinstance(packet, Ether):
            ip_packet = packet.payload
        else:
            ip_packet = packet.payload

        logger.debug("Handling a packet!")
        tcp_packet = ip_packet.payload

        # This can also be done using packet.payload.dport
        source_port = tcp_packet.dport
        destination_port = tcp_packet.sport

        if destination_port == self.real_open_port:
            return

        flags = tcp_packet.sprintf("%TCP.flags%")

        return_flags = "A"

        if "S" in flags:
            return_flags += "S"

        if "F" in flags:
            return_flags += "F"

        sequence_number = random.randint(0, 65535)
        ack_number = tcp_packet.seq + 1

        source_ip = ip_packet.dst
        destination_ip = ip_packet.src

        try:
            ip_reply_packet = IP(src=source_ip, dst=destination_ip)
        except:
            logger.exception("Exception building IP packet: src={}, dst={}".format(source_ip, destination_ip))
            pdb.set_trace()
        else:
            try:
                tcp_reply_packet = TCP(sport=source_port, dport=destination_port, seq=sequence_number, ack=ack_number, flags=return_flags)
            except:
                logger.exception("Exception building TCP packet")
            else:
                try:
                    reply_packet = ip_reply_packet/tcp_reply_packet
                except:
                    logger.exception("Exception composing packets")
                else:
                    logger.info("Sending a reply to: {}:{}".format(source_ip, source_port))
                    self.sending_socket.send(reply_packet)

    def handle_data(self, data):
        pass

    def handle_stream(self, stream, address):
        stream.read_until_close(streaming_callback=self.handle_data)


if __name__ == "__main__":
    io_loop = IOLoop()
    server = FakeOpenServer(io_loop=io_loop)
    server.listen(9000)
    io_loop.start()
