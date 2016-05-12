import argparse
import functools
import itertools
import logging
import socket
import ssl
import time

from tornado import ioloop, gen, queues
from tornado.iostream import IOStream, SSLIOStream, StreamClosedError
from tornado.simple_httpclient import SimpleAsyncHTTPClient
from tornado.httpclient import AsyncHTTPClient

__author__ = 'bennettaur'


class BaseAttackRunner(object):

    def __init__(self, io_loop, ip_list, ports, concurrency, rate, request_timeout):
        self.io_loop = io_loop
        self.ip_list = ip_list
        self.ports = ports
        self.concurrency = concurrency
        self.rate = rate
        self.request_timeout = request_timeout
        self.result_file = open("results.csv", "w")

        self.start = None
        self.requests_started = 0
        self.queue = queues.Queue()
        self.attack_map = itertools.product(self.ports, self.ip_list)

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
        # Start consumer without waiting (since it never finishes).
        for _ in xrange(self.concurrency):
            self.io_loop.spawn_callback(self.consumer)
        yield self.producer()     # Wait for producer to put all tasks.
        yield self.queue.join()       # Wait for consumer to finish all tasks.
        self.io_loop.stop()


class HTTPAttackRunner(BaseAttackRunner):

    def __init__(self, io_loop, ip_list, ports, concurrency, rate, request_timeout, path, https, use_curl):
        super(HTTPAttackRunner, self).__init__(io_loop, ip_list, ports, concurrency, rate, request_timeout)
        self.path = path
        self.protocol = "https://" if https else "http://"
        self.result_file = open("results.csv", "w")

        if use_curl:
            from tornado.curl_httpclient import CurlAsyncHTTPClient
            AsyncHTTPClient.configure(CurlAsyncHTTPClient, max_clients=self.concurrency)
        else:
            AsyncHTTPClient.configure(SimpleAsyncHTTPClient, max_clients=self.concurrency)
        self.http_client = AsyncHTTPClient(io_loop=self.io_loop)

    @gen.coroutine
    def consumer(self):
        http_client = AsyncHTTPClient(io_loop=self.io_loop, force_instance=True)
        while True:

            now = time.time()

            elapsed_time = now - self.start
            current_rate = self.requests_started/elapsed_time

            if 0 < self.rate < current_rate:
                delay = (self.requests_started - (self.rate * elapsed_time))/self.rate
                print "Current rate is {} so we're throttling! Sleeping for {} seconds".format(current_rate, delay)
                yield gen.sleep(delay)
            port, ip = yield self.queue.get()

            self.requests_started += 1

            target = "".join([self.protocol, ip, ":", str(port), self.path])
            #print "Scanning {}".format(target)

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
                        self.result_file.flush()
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


class TCPHTTPAttackRunner(BaseAttackRunner):

    PAYLOAD = [
        "GET {path} HTTP/1.0\r\n",
        "",
        "",
        "\r\n",
    ]
    DEFAULT_USER_AGENT = (
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_11_4) "
        "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/50.0.2661.86 Safari/537.36"
    )

    def __init__(self,
                 io_loop,
                 ip_list,
                 ports,
                 concurrency,
                 rate,
                 request_timeout,
                 path,
                 try_ssl,
                 user_agent=None,
                 host=None,
                 use_ip_as_host=False):
        super(TCPHTTPAttackRunner, self).__init__(io_loop, ip_list, ports, concurrency, rate, request_timeout)
        self.path = path
        self.ssl = try_ssl
        self.use_ip_as_host = use_ip_as_host
        self.result_file = open("results.csv", "w")
        self.ssl_context = ssl._create_unverified_context()

        self.payload = [
            "GET {path} HTTP/1.0\r\n".format(path=self.path),
            "",
            "",
            "\r\n",
        ]

        if host is not None:
            host_header = "Host: {}\r\n".format(host)
            self.payload[1] = host_header

        user_agent_header = "User-Agent: {}\r\n".format((user_agent or self.DEFAULT_USER_AGENT))
        self.payload[2] = user_agent_header

    @staticmethod
    def close_stream(stream):
        try:
            stream.close()
        except:
            pass

    @gen.coroutine
    def consumer(self):
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

                result = ''

                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0)
                iostream = IOStream(s)

                callback = functools.partial(self.close_stream, iostream)

                timeout = self.io_loop.call_later(self.request_timeout, callback)

                self.requests_started += 1
                ssl_success = False

                try:
                    yield iostream.connect((ip, port))
                except StreamClosedError:
                    pass
                except:
                    logging.exception("Error connecting to {}:{}".format(ip, port))
                else:
                    if self.ssl:
                        try:
                            iostream = yield iostream.start_tls(False, ssl_options=self.ssl_context)
                        except:
                            try:
                                iostream.close()
                            except:
                                pass
                            # SSL failed, need to recreate the connection
                            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0)
                            iostream = IOStream(s)

                            ssl_success = False
                            try:
                                self.io_loop.remove_timeout(timeout)
                            except:
                                pass

                            timeout = self.io_loop.call_later(self.request_timeout, callback)

                            try:
                                yield iostream.connect((ip, port))
                            except:
                                logging.exception("Error re-connecting to {}:{} after ssl attempt".format(ip, port))
                        else:
                            ssl_success = True

                    try:
                        # finish building the request payload
                        if self.use_ip_as_host and self.payload[1] == "":
                            self.payload[1] = "Host: {}\r\n".format(ip)

                        payload = "".join(self.payload)

                        yield iostream.write(payload)
                    except StreamClosedError:
                        pass
                    except:
                        logging.exception("Exception while trying to write to {}:{}".format(ip, port))
                    else:
                        try:
                            result = yield iostream.read_until('\r\n')
                        except StreamClosedError:
                            pass
                        except:
                            logging.exception("Exception while trying to read from {}:{}".format(ip, port))

                try:
                    self.io_loop.remove_timeout(timeout)
                except:
                    pass

                try:
                    iostream.close()
                except:
                    pass

                if len(result) > 0 or ssl_success:
                    result_string = result.strip()
                    if ssl_success:
                        result_string += " + SSL"
                    self.result_file.write("{}, {}, {}\n".format(ip, port, result_string))
                    self.result_file.flush()

            except:
                logging.exception("Consumer almost crashed from uncaught error")
            finally:
                try:
                    self.queue.task_done()
                except queues.QueueEmpty:
                    pass
                except ValueError:
                    logging.exception("A worker got a ValueError while marking a task as done")


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
        default=3,
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
    parser.add_argument(
        '-z',
        '--http_client',
        default=False,
        action='store_true',
        help="Use a proper HTTP client (Good if you need proper http support)"
    )
    parser.add_argument(
        '-a',
        '--user_agent',
        default=None,
        help="User Agent String to send with requests"
    )
    parser.add_argument(
        '-q',
        '--host_header',
        default=None,
        help="Host header String to send with requests"
    )
    parser.add_argument(
        '-v',
        '--use_ip_as_host',
        default=False,
        action='store_true',
        help="Attempt to use the supplied IP/domain as the Host header String to send with requests"
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

    if args.http_client:
        runner = HTTPAttackRunner(
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
    else:

        runner = TCPHTTPAttackRunner(
            io_loop,
            ip_list,
            ports,
            args.concurrency,
            args.rate,
            args.request_timeout,
            args.path,
            args.https,
            args.user_agent,
            args.host_header,
            args.use_ip_as_host
        )

    io_loop.add_callback(runner.run)
    io_loop.start()

    print "Finished running!"

if __name__ == "__main__":
    main()
