import logging
import random
import time

from tornado import gen, queues
from tornado.concurrent import Future
from tornado.ioloop import IOLoop

from scapy.all import IP, TCP

from scan_runners.base_runner import BaseScanRunner
from utils.layer3 import Layer3Socket
from utils.sniffer import TCPDumpSniffer

__author__ = 'bennettaur'


"""
The general idea works like this: Some appliance fakes that all ports are open, i.e. replies to syn's with syn-acks.
Bypass it by checking the validitiy of the TCP connection, i.e. try to interact with it.

General methodology (sync):
1) Send SYN packet
2) Wait for SYN-ACK
3) Send TCP Keepalive
4) If Keepalive doesn't return, try sending an empty packet, or single byte packet
5) If single or empty byte packet doesn't work, send FIN pack
6) IF no FIN-ACK and FIN packet it probably really is closed
"""


class ConnectionTester(object):

    START = 0
    SYN_SENT = 1
    SYN_ACK_ACK_SENT = 2
    TCP_KEEPALIVE_SENT = 3
    EMPTY_PACKET_SENT = 4
    ONE_BYTE_PACKET_SENT = 4
    FIN_SENT = 5
    FIN_ACK_SENT = 6

    PACKET_DELAY = 1

    def __init__(self, ip, dport, sport, sending_socket, run_sync, continue_on_success, io_loop=None):
        self.io_loop = io_loop or IOLoop.current()
        self.ip = ip
        self.dport = int(dport)
        self.sport = sport
        self.sending_socket = sending_socket
        self.run_sync = run_sync
        self.continue_on_success = continue_on_success
        self.future = None

        self.start_sequence_number = random.randint(0, 65536)
        self.sequence_number = self.start_sequence_number
        self.ack_number = -1
        self.ip_packet = IP(dst=ip)

        self.syn_acked = None
        self.tcp_keepalive_success = None
        self.empty_packet_success = None
        self.one_byte_packet_success = None
        self.fin_acked = None
        self.fin_received = None

        self.timeout = None

        self.state = self.START

    def receive_packet(self, packet):
        old_ack = self.ack_number
        old_seq = self.sequence_number

        self.ack_number = packet.seq + 1
        self.sequence_number = packet.ack

        tcp_packet = packet.payload

        flags = tcp_packet.sprintf("%TCP.flags%")

        if "R" in flags:
            logging.info("Connection reset")
            return
        elif "F" in flags:
            self.fin_received = True
            if "A" in flags and self.state == self.FIN_SENT:
                self.fin_acked = True
            elif self.state != self.FIN_SENT:
                logging.info("Client is closing connection without FIN")


            self.send_fin_ack()
            return

        elif self.state == self.SYN_SENT:
            if "S" in flags and "A" in flags:
                self.syn_acked = True

                if self.run_sync:
                    self.send_syn_ack_ack()
                    self.io_loop.call_later(self.PACKET_DELAY, self.send_tcp_keepalive)
                    self.timeout = self.io_loop.call_later(self.PACKET_DELAY * 2, self.send_empty_packet)

                return

        elif self.state == self.TCP_KEEPALIVE_SENT:
            if "A" in flags:
                if self.timeout is not None:
                    self.io_loop.remove_timeout(self.timeout)
                    self.timeout = None
                self.tcp_keepalive_success = True

                if not self.continue_on_success:
                    self.send_fin()
                    return

                if self.run_sync:
                    self.send_empty_packet()
                    self.timeout = self.io_loop.call_later(self.PACKET_DELAY, self.send_one_byte_packet)

                return

        elif self.state == self.EMPTY_PACKET_SENT:
            if "A" in flags:
                if self.timeout is not None:
                    self.io_loop.remove_timeout(self.timeout)
                    self.timeout = None
                self.empty_packet_success = True
                if not self.continue_on_success:
                    self.send_fin()
                    return

                if self.run_sync:
                    self.send_one_byte_packet()
                    self.timeout = self.io_loop.call_later(self.PACKET_DELAY, self.send_fin)

                return

        elif self.state == self.ONE_BYTE_PACKET_SENT:
            if "A" in flags:
                if self.timeout is not None:
                    self.io_loop.remove_timeout(self.timeout)
                    self.timeout = None
                self.one_byte_packet_success = True
                if not self.continue_on_success:
                    self.send_fin()
                    return

                if self.run_sync:
                    self.send_fin()

                return

        logging.warning("Out of state packet received. Ignoring\n{}".format(packet))

        self.ack_number = old_ack
        self.sequence_number = old_seq

    @staticmethod
    def handle_timeout(next_send_function):
        next_send_function()

    def send_syn(self):
        packet = self.ip_packet / TCP(dport=self.dport, seq=self.sequence_number, flags="S")
        self.sending_socket.send(packet)
        self.state = self.SYN_SENT
        self.syn_acked = False

    def send_syn_ack_ack(self):
        # Send ACK for SYN-ACK
        packet = self.ip_packet / TCP(dport=self.dport, seq=self.sequence_number, ack=self.ack_number, flags="A")
        self.sending_socket.send(packet)
        self.state = self.SYN_ACK_ACK_SENT

    def send_tcp_keepalive(self):
        packet = self.ip_packet / TCP(dport=self.dport, seq=self.sequence_number - 1, ack=self.ack_number, flags="A")
        self.sending_socket.send(packet)
        self.state = self.TCP_KEEPALIVE_SENT
        self.tcp_keepalive_success = False

    def send_empty_packet(self):
        packet = self.ip_packet / TCP(dport=self.dport, seq=self.sequence_number, ack=self.ack_number)
        self.sending_socket.send(packet)
        self.state = self.EMPTY_PACKET_SENT
        self.empty_packet_success = False

    def send_one_byte_packet(self):
        packet = self.ip_packet / TCP(dport=self.dport, seq=self.sequence_number, ack=self.ack_number) / " "
        self.sending_socket.send(packet)
        self.state = self.ONE_BYTE_PACKET_SENT
        self.one_byte_packet_success = False

    def send_fin(self):
        packet = self.ip_packet / TCP(dport=self.dport, seq=self.sequence_number, ack=self.ack_number, flags="F")
        self.sending_socket.send(packet)
        self.state = self.FIN_SENT
        self.fin_acked = False

    def send_fin_ack(self):
        packet = self.ip_packet / TCP(dport=self.dport, seq=self.sequence_number, ack=self.ack_number, flags="FA")
        self.sending_socket.send(packet)
        self.state = self.FIN_ACK_SENT


class TCPScanRunner(BaseScanRunner):

    def __init__(self,
                 io_loop,
                 ip_list,
                 ports,
                 concurrency,
                 rate,
                 request_timeout,
                 source_port,
                 source_ip=None,
                 run_sync=True,
                 async_wait=1,
                 continue_on_success=True):
        super(TCPScanRunner, self).__init__(io_loop, ip_list, ports, concurrency, rate, request_timeout)

        self.source_port = source_port
        self.source_ip = source_ip
        self.run_sync = run_sync
        self.async_wait = async_wait
        self.continue_on_success = continue_on_success

        self.sending_socket = Layer3Socket()

        self.connection_map = {
            (port, ip):
                ConnectionTester(
                    ip,
                    port,
                    self.source_port,
                    self.sending_socket,
                    self.run_sync,
                    self.continue_on_success,
                    self.io_loop
                )
            for port, ip in self.attack_map
        }

        self.sniffer = TCPDumpSniffer(
            io_loop=self.io_loop,
            prn=self.handle_receive_packet,
            filter="host {} and dst port {}".format(self.source_ip, self.source_port)
        )

        # Generate SYN
        # Generate TCP Keepalive
        # Generate empty
        # Generate FIN

        # Set firewall rules to not send RST packets

    def handle_receive_packet(self, packet):

        port = packet.sport
        ip = packet.layer.src  # look up how to actually do this

        try:
            conn_tester = self.connection_map[(port, ip)]
        except KeyError:
            logging.info("Got an unknown packet: {}:{}".format(ip, port))
            return

        conn_tester.receive_packet(packet)

    @gen.coroutine
    def consumer(self):
        self.active_workers += 1
        while True:
            try:
                now = time.time()

                elapsed_time = now - self.start
                current_rate = self.requests_started/elapsed_time

                if 0 < self.rate < current_rate:
                    delay = (self.requests_started - (self.rate * elapsed_time))/self.rate
                    print "Current rate is {} so we're throttling! Sleeping for {} seconds".format(current_rate, delay)
                    yield gen.sleep(delay)
                port, ip = yield self.queue.get()

                try:
                    conn_tester = self.connection_map[(port, ip)]
                except KeyError:
                    logging.info("Missing Conn tester for: {}:{}".format(ip, port))
                    continue

                self.requests_started += 1

                try:
                    """
                    SYNC RUN:
                    yield SYN
                    if SYN-ACK: yield TCP Keepalive
                    if not TCP keepalive: yield empty packet
                    if not empty packet: yield FIN

                    Async Run:
                    yield SYN
                    wait X seconds: yield TCP Keepalive
                    wait X seconds: yield empty packet
                    wait X seconds: yield FIN
                    """

                    if self.run_sync:
                        conn_tester.send_syn()
                    else:
                        self.async_send(conn_tester)

                except:
                    logging.exception("Exception while trying to scan {}:{}".format(ip, port))
            except:
                logging.exception("Consumer almost crashed from uncaught error")
            finally:
                self.completed_scans.append((port, ip))
                try:
                    self.queue.task_done()
                except queues.QueueEmpty:
                    pass
                except ValueError:
                    logging.exception("A worker got a ValueError while marking a task as done")
        self.active_workers -= 1

    def async_send(self, conn_tester):
        if conn_tester.state == conn_tester.START:
            conn_tester.send_syn()

        elif conn_tester.state == conn_tester.SYN_SENT:
            conn_tester.send_syn_ack_ack()

        elif conn_tester.state == conn_tester.SYN_ACK_ACK_SENT:
            conn_tester.send_tcp_keepalive()

        elif conn_tester.state == conn_tester.TCP_KEEPALIVE_SENT:
            conn_tester.send_empty_packet()

        elif conn_tester.state == conn_tester.EMPTY_PACKET_SENT:
            conn_tester.send_one_byte_packet()

        elif conn_tester.state == conn_tester.ONE_BYTE_PACKET_SENT:
            conn_tester.send_fin()
        else:
            # No other steps to be done, just return
            return

        self.io_loop.call_later(self.async_wait, self.async_send, conn_tester)

    @gen.coroutine
    def run(self):


        yield super(TCPScanRunner, self).run()