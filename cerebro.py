import argparse
import itertools
import logging
import time

from tornado import ioloop, gen, queues
from tornado.simple_httpclient import SimpleAsyncHTTPClient
from tornado.httpclient import AsyncHTTPClient

__author__ = 'bennettaur'


class AttackRunner(object):

    def __init__(self, io_loop, ip_list, ports, concurrency, rate, request_timeout, path, https, use_curl):
        self.io_loop = io_loop
        self.ip_list = ip_list
        self.ports = ports
        self.concurrency = concurrency
        self.rate = rate
        self.request_timeout = request_timeout
        self.path = path
        self.protocol = "https://" if https else "http://"
        self.result_file = open("results.csv", "w")

        if use_curl:
            from tornado.curl_httpclient import CurlAsyncHTTPClient
            AsyncHTTPClient.configure(CurlAsyncHTTPClient, max_clients=self.concurrency)
        else:
            AsyncHTTPClient.configure(SimpleAsyncHTTPClient, max_clients=self.concurrency)
        self.http_client = AsyncHTTPClient(io_loop=self.io_loop)
        self.queue = queues.Queue()
        self.attack_map = itertools.product(self.ports, self.ip_list)

    @gen.coroutine
    def producer(self):
        start = time.time()
        requests_started = 0
        for port_ip in self.attack_map:
            yield self.queue.put(port_ip)
            now = time.time()
            requests_started += 1

            elapsed_time = now - start
            current_rate = requests_started/elapsed_time

            if 0 < self.rate < current_rate:
                delay = (requests_started - (self.rate * elapsed_time))/self.rate
                print "Current rate is {} so we're throttling! Sleeping for {} seconds".format(current_rate, delay)
                yield gen.sleep(delay)

    @gen.coroutine
    def consumer(self):
        http_client = AsyncHTTPClient(io_loop=self.io_loop, force_instance=True)
        while True:
            port, ip = yield self.queue.get()

            target = "".join([self.protocol, ip, ":", str(port), self.path])
            print "Scanning {}".format(target)

            try:
                result = yield http_client.fetch(
                    target,
                    raise_error=False,
                    decompress_response=False,
                    follow_redirects=False,
                    connect_timeout=self.request_timeout,
                    request_timeout=self.request_timeout
                )
            except:
                logging.exception("Exception while trying to scan {}:{}".format(ip, port))
            else:
                try:
                    if result.code != 599:
                        self.result_file.write("{},{},{}\n".format(ip, port, result.code))
                except AttributeError:
                    pass
                except:
                    logging.exception("Exception while handling the response from {}:{}".format(ip, port))

            try:
                self.queue.task_done()
            except queues.QueueEmpty:
                pass
            except ValueError:
                logging.exception("A worker got a ValueError while marking a task as done")

    @gen.coroutine
    def run(self):
        # Start consumer without waiting (since it never finishes).
        for _ in xrange(self.concurrency):
            self.io_loop.spawn_callback(self.consumer)
        yield self.producer()     # Wait for producer to put all tasks.
        yield self.queue.join()       # Wait for consumer to finish all tasks.
        self.io_loop.stop()


def main():

    parser = argparse.ArgumentParser()

    parser.add_argument('-i', '--ip_file', type=str, help="The path to the file containing the IPs to scan")
    parser.add_argument('-p', '--ports', type=str, help="The ports to scan seperated by commas. Ex -p 80,443,1000-2000")
    parser.add_argument(
        '-c',
        '--concurrency',
        type=int,
        default=1000,
        help="The number of simultaneous connections that are allowed. Default is unlimited"
    )
    parser.add_argument(
        '-r',
        '--rate',
        type=int,
        default=0,
        help="The target rate to do the scan at, in requests per second"
    )
    parser.add_argument(
        '-f',
        '--force',
        default=False,
        action='store_true',
        help=("Force this to run with no limits. WARNING you could unintentionally be doing a DDoS attack "
              "by using this. You should verify this is what you want and possibly talk to Michael @ DDoS Strike"
              "for more guidance on setting rate and concurrency")
    )
    parser.add_argument(
        '-t',
        '--request_timeout',
        type=int,
        default=2,
        help="How long to wait before timing out a request in seconds. Default is 2"
    )
    parser.add_argument(
        '-d',
        '--path',
        type=str,
        default="/",
        help="The path to attempt to request from the server"
    )
    parser.add_argument(
        '-s',
        '--https',
        default=False,
        action='store_true',
        help="Use HTTPS when making requests"
    )
    parser.add_argument(
        '-u',
        '--use_curl',
        default=False,
        action='store_true',
        help="Use curl when making requests"
    )

    args = parser.parse_args()

    if args.rate == args.concurrency == 0 and not args.force:
        print ("ERROR! Rate and concurrency are set to unlimited. This could potentially become a DDoS attack against "
               "whoever you are scanning. If you a absolutely positive this is what you want, please re-run with the "
               "-f (force) option. If you're not sure, please contact Michael @ DDoS Strike for some guidance.")
        return

    with open(args.ip_file, 'r') as ip_file:
        ip_list = [ip.strip() for ip in ip_file]

    ports = []
    for port in args.ports.split(','):
        if "-" in port:
            port_range = port.split("-")
            if len(port_range) != 2:
                raise Exception("Bad port range specified: {}".format(port))

            ports.extend(xrange(int(port_range[0]), int(port_range[1]) + 1))
        else:
            ports.append(int(port))

    io_loop = ioloop.IOLoop.current()

    runner = AttackRunner(
        io_loop,
        ip_list,
        ports,
        args.concurrency,
        args.rate,
        args.request_timeout,
        args.path,
        args.https,
        args.use_curl
    )

    io_loop.add_callback(runner.run)
    io_loop.start()

    print "Finished running!"

if __name__ == "__main__":
    main()
