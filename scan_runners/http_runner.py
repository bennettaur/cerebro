import functools
import logging
import socket
import ssl
import time

from tornado import gen, queues
from tornado.httpclient import AsyncHTTPClient
from tornado.iostream import IOStream, StreamClosedError
from tornado.simple_httpclient import SimpleAsyncHTTPClient

from scan_runners.base_runner import BaseScanRunner

__author__ = 'bennettaur'


class HTTPScanRunner(BaseScanRunner):

    def __init__(self, io_loop, ip_list, ports, concurrency, rate, request_timeout, path, https, use_curl):
        super(HTTPScanRunner, self).__init__(io_loop, ip_list, ports, concurrency, rate, request_timeout)
        self.path = path
        self.protocol = "https://" if https else "http://"

        if use_curl:
            from tornado.curl_httpclient import CurlAsyncHTTPClient
            AsyncHTTPClient.configure(CurlAsyncHTTPClient, max_clients=self.concurrency)
        else:
            AsyncHTTPClient.configure(SimpleAsyncHTTPClient, max_clients=self.concurrency)
        self.http_client = AsyncHTTPClient(io_loop=self.io_loop)

    @gen.coroutine
    def consumer(self):
        http_client = AsyncHTTPClient(io_loop=self.io_loop, force_instance=True)
        self.active_workers += 1
        while True:
            success = False
            try:
                now = time.time()

                elapsed_time = now - self.start
                current_rate = self.requests_started/elapsed_time

                if elapsed_time > 2 and 0 < self.rate < current_rate:
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
                    success = True
                    try:
                        if result.code != 599:
                            self.result_file.write("{},{},{}\n".format(ip, port, result.code))
                            self.result_file.flush()
                    except AttributeError:
                        pass
                    except:
                        logging.exception("Exception while handling the response from {}:{}".format(ip, port))
            except:
                logging.exception("Consumer almost crashed from uncaught error")
            finally:
                self.progress_file.write("{},{}\n".format(port, ip))
                self.completed_scans.append((port, ip))
                try:
                    self.queue.task_done()
                except queues.QueueEmpty:
                    pass
                except ValueError:
                    logging.exception("A worker got a ValueError while marking a task as done")

        self.active_workers -= 1


class TCPHTTPScanRunner(BaseScanRunner):

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
        super(TCPHTTPScanRunner, self).__init__(io_loop, ip_list, ports, concurrency, rate, request_timeout)
        self.path = path
        self.ssl = try_ssl
        self.use_ip_as_host = use_ip_as_host
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
        self.active_workers += 1
        while True:
            try:
                now = time.time()

                elapsed_time = now - self.start
                current_rate = self.requests_started/elapsed_time

                if elapsed_time > 2 and 0 < self.rate < current_rate:
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
                    self.result_file.write("{}, {}, {}, {}\n".format(ip, port, result_string, ssl_success))
                    self.result_file.flush()

            except:
                logging.exception("Consumer almost crashed from uncaught error")
            finally:
                self.progress_file.write("{},{}\n".format(port, ip))
                self.completed_scans.append((port, ip))
                try:
                    self.queue.task_done()
                except queues.QueueEmpty:
                    pass
                except ValueError:
                    logging.exception("A worker got a ValueError while marking a task as done")

        self.active_workers -= 1
