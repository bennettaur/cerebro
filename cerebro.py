import argparse

from tornado import ioloop

from scan_runners.http_runner import HTTPScanRunner, TCPHTTPScanRunner

__author__ = 'bennettaur'


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
        runner = HTTPScanRunner(
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

        runner = TCPHTTPScanRunner(
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
