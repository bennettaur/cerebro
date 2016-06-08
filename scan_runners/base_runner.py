import itertools
import pprint
import logging
import time

from tornado import queues, gen
from tornado.ioloop import PeriodicCallback

__author__ = 'bennettaur'


class BaseScanRunner(object):

    def __init__(self, io_loop, ip_list, ports, concurrency, rate, request_timeout, idle_timeout=15000):
        self.io_loop = io_loop
        self.ip_list = ip_list
        self.ports = ports
        self.concurrency = concurrency
        self.rate = rate
        self.request_timeout = request_timeout
        self.idle_timeout = idle_timeout

        self.last_checked_complete_size = 0
        self.active_workers = 0

        self.result_file = open("results.csv", "w")

        self.start = None
        self.requests_started = 0
        self.completed_scans = []
        self.queue = queues.Queue()
        self.attack_map = itertools.product(self.ports, self.ip_list)

        self.idle_checker = PeriodicCallback(self.check_for_idle, self.idle_timeout)

    def check_for_idle(self):
        completed_count = len(self.completed_scans)
        if self.last_checked_complete_size <= completed_count:
            logging.info("Scan has be idle for {}. Stopping it now.".format(self.idle_timeout))
            self.io_loop.stop()

            # Check which scans didn't get run
            targeted = set(itertools.product(self.ports, self.ip_list))
            completed = set(self.completed_scans)

            incomplete = ["{}:{}".format(ip, port) for port, ip in (targeted - completed)]
            incomplete.sort()

            print "The following IP:Port combos did not complete:\n{}".format(pprint.pformat(incomplete))

        else:
            self.last_checked_complete_size = completed_count

    @gen.coroutine
    def producer(self):
        for port_ip in self.attack_map:
            yield self.queue.put(port_ip)

    @gen.coroutine
    def consumer(self):
        raise NotImplementedError

    @gen.coroutine
    def run(self):
        self.start = time.time()
        # Start the idle watcher
        self.idle_checker.start()
        # Start consumer without waiting (since it never finishes).
        for _ in xrange(self.concurrency):
            self.io_loop.spawn_callback(self.consumer)
        yield self.producer()     # Wait for producer to put all tasks.
        yield self.queue.join()       # Wait for consumer to finish all tasks.

        self.result_file.close()
        self.io_loop.stop()
