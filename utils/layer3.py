from scapy.packet import Gen
from scapy.base_classes import SetGen
from scapy.config import conf
from scapy.all import IP, TCP
from utils.misc import setup_logging

__author__ = 'bennettaur'


logger = setup_logging(__name__)


class Layer3Socket(object):

    def __init__(self, socket_kwargs=None):

        self.socket_kwargs = socket_kwargs or {}
        self.socket = None

        self.create_socket()

    def create_socket(self):
        self.socket = conf.L3socket(**self.socket_kwargs)

    def close(self):
        try:
            self.socket.close()
        except:
            logger.exception("Exception while trying to close a scapy L3 Socket")

    def recreate_socket(self):
        if self.socket is not None:
            self.close()

        self.create_socket()

    def send(self, x):
        if type(x) is str:
            x = conf.raw_layer(load=x)
        if not isinstance(x, Gen):
            x = SetGen(x)

        socket_fails = 0

        for p in x:
            try:
                self.socket.send(p)
            except:
                logger.exception("Exception while trying to send data")
                if socket_fails < 5:
                    self.recreate_socket()
                    socket_fails += 1
                else:
                    raise
