__author__ = 'bennettaur'

import os
import struct
import time

from tornado.ioloop import IOLoop
from tornado.process import Subprocess
from tornado import gen
from tornado.iostream import StreamClosedError

from scapy.all import plist, MTU, PcapReader, conf

from utils.misc import setup_logging

logger = setup_logging(__name__)


class TCPDumpSniffer(object):

    interfaces = {
        'eth0': 1,
        'any': 2,
        'lo': 3
    }

    directions = ['in', 'out', 'inout']

    def __init__(self,
                 io_loop=None,
                 count=0,
                 store=1,
                 offline=None,
                 prn=None,
                 lfilter=None,
                 L2socket=None,
                 timeout=None,
                 opened_socket=None,
                 stop_filter=None,
                 filter=None,
                 iface=None,
                 direction=None,
                 count_trigger=-1,
                 count_triggered_function=None):
        """
        A copy of Scapy's sniff function, adapted to run using the tornado IOLoop.
        Note if something blocks the tornado IOLoop, this runs the risk of missing packets, as it won't "drain" the pcap
        reader since it would eventually cause it to block when it tries to call next on the object and there isn't
        anything waiting.

        Sniff packets
        sniff([count=0,] [prn=None,] [store=1,] [offline=None,] [lfilter=None,] + L2ListenSocket args) -> list of packets

          count: number of packets to capture. 0 means infinity
          store: wether to store sniffed packets or discard them
            prn: function to apply to each packet. If something is returned,
                 it is displayed. Ex:
                 ex: prn = lambda x: x.summary()
        lfilter: python function applied to each packet to determine
                 if further action may be done
                 ex: lfilter = lambda x: x.haslayer(Padding)
        offline: pcap file to read packets from, instead of sniffing them
        timeout: stop sniffing after a given time (default: None)
        L2socket: use the provided L2socket
        opened_socket: provide an object ready to use .recv() on
        stop_filter: python function applied to each packet to determine
                     if we have to stop the capture after this packet
                     ex: stop_filter = lambda x: x.haslayer(TCP)
        """
        self.io_loop = io_loop or IOLoop.current()
        self.max_captured_count = count
        self.bytes = 0
        self.store = store
        self.offline = offline
        self.prn = prn
        self.lfilter = lfilter
        self.timeout = timeout
        self.opened_socket = opened_socket
        self.stop_filter = stop_filter
        self.iface = self.interfaces.get(iface, None) or iface
        self.filter = filter
        self.direction = direction
        self.count_trigger = count_trigger
        self.count_triggered_function = count_triggered_function

        self.start_time = None
        self.last_record_time = 0
        self.captured_count = 0
        self.byte_count = 0
        self.capture_socket = None
        self.captured_list = None
        self.stoptime = 0
        self.remain = None
        self.handler = None
        self.tcpdump_command = None
        self.tcpdump_process = None
        self.tcpdump_error_stream = None

        self.running = False
        self.last_return_status = None

        self.raw_buffer = []

    @staticmethod
    def handle_error_stream(data):
        logger.info("Logged stderr from subprocess:\n{}".format(data))

    def build_tcpdump_command(self):
        command = ['tcpdump', "-w", "-", "-U"]
        if self.iface is not None:
            command.append("-i")
            command.append("{}".format(self.iface))

        if self.max_captured_count > 0:
            command.append("-c")
            command.append("{}".format(self.max_captured_count))

        if self.direction is not None:
            if self.direction in self.directions:
                command.append("-Q")
                command.append("{}".format(self.direction))
            else:
                logger.warning("Invalid direction specified: {}".format(self.direction))

        command.append(self.filter)
        return command

    def start(self):
        self.start_time = time.time()
        self.last_record_time = 0
        self.captured_count = 0
        self.byte_count = 0
        self.running = True

        Subprocess.initialize(self.io_loop)
        self.tcpdump_process = Subprocess(
            self.build_tcpdump_command(),
            stdout=Subprocess.STREAM,
            stderr=Subprocess.STREAM,
            io_loop=self.io_loop,
        )
        self.capture_socket = self.tcpdump_process.stdout
        self.tcpdump_error_stream = self.tcpdump_process.stderr
        self.tcpdump_error_stream.read_until_close(streaming_callback=self.handle_error_stream)

        self.captured_list = []
        if self.timeout is not None:
            print "Set a timeout for {}".format(self.timeout)
            self.io_loop.call_later(self.stop, self.timeout)
        self.remain = None

        return self.sniff()

    @gen.coroutine
    def stop(self):
        self.running = False
        if self.tcpdump_process.proc.poll() is None:
            self.tcpdump_process.proc.terminate()
        if self.capture_socket is not None:
            print "Closing the capture socket"
            self.capture_socket.close()

        self.last_return_status = yield self.tcpdump_process.wait_for_exit()

    def peek_sniffed_packets(self):
        return plist.PacketList(self.captured_list, "Sniffed")

    def empty_sniffed_packets(self):
        packet_list = plist.PacketList(self.captured_list, "Sniffed")
        self.captured_list = []
        return packet_list

    @gen.coroutine
    def sniff(self):
        magic = yield self.capture_socket.read_bytes(4)
        if magic == "\xa1\xb2\xc3\xd4": #big endian
            endian = ">"
        elif magic == "\xd4\xc3\xb2\xa1": #little endian
            endian = "<"
        else:
            raise Exception("Bad Magic reading from TCPDUMP output")

        hdr = yield self.capture_socket.read_bytes(20)
        if len(hdr) < 20:
            raise Exception("Bad header read from TCPDUMP output")
        vermaj, vermin, tz, sig, snaplen, linktype = struct.unpack(endian + "HHIIII", hdr)

        link_layer_cls = conf.l2types[linktype]

        while self.running:
            try:
                hdr = yield self.capture_socket.read_bytes(16, partial=True)
                if len(hdr) < 16:
                    break

                sec, usec, caplen, wirelen = struct.unpack(endian + "IIII", hdr)
                raw_p = yield self.capture_socket.read_bytes(caplen, partial=True)

                if raw_p is None:
                    continue

                try:
                    p = link_layer_cls(raw_p)
                except KeyboardInterrupt:
                    raise
                except:
                    if conf.debug_dissector:
                        raise
                    p = conf.raw_layer(raw_p)

                self.byte_count += len(p)

                if self.lfilter and not self.lfilter(p):
                    break
                if self.store:
                    self.captured_list.append(p)
                self.captured_count += 1
                if self.prn:
                    r = self.prn(p)
                    if r is not None:
                        print r

                if (self.count_triggered_function is not None and
                            self.captured_count is not None and
                            self.captured_count >= self.count_trigger):
                    self.count_triggered_function()

                if self.stop_filter and self.stop_filter(p):
                    break
                if 0 < self.max_captured_count <= self.captured_count:
                    break
            except (KeyboardInterrupt, StreamClosedError):
                break

        if self.running:
            print "Exited the sniff loop, going to stop the sniffer"
            self.stop()

        raise gen.Return(plist.PacketList(self.captured_list, "Sniffed"))
