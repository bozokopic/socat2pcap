from pathlib import Path
import argparse
import contextlib
import sys

from socat2pcap.pcap import PcapStream
from socat2pcap.socat import SocatStream


def create_argument_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Convert socat log to pcap")
    parser.add_argument(
        '--output', metavar='PATH', type=Path, default=Path('-'),
        help="output pcap path or '-' for stdout (default '-')")
    parser.add_argument(
        '--with-text', action='store_true',
        help="sockat log was generated with -x and -v flag "
             "(without this flag, only -x is expected)")
    parser.add_argument(
        '--ip-addr-a', metavar='ADDR', default='127.0.0.1',
        help="first ip address (default '127.0.0.1')")
    parser.add_argument(
        '--ip-addr-b', metavar='ADDR', default='127.0.0.1',
        help="second ip address (default '127.0.0.1')")
    parser.add_argument(
        '--tcp-port-a', metavar='PORT', type=int, default=1234,
        help="first tcp port (default 1234)")
    parser.add_argument(
        '--tcp-port-b', metavar='PORT', type=int, default=4321,
        help="second tcp port (default 4321)")
    parser.add_argument(
        'input', metavar='PATH', type=Path, default=Path('-'), nargs='?',
        help="input socat log path or '-' for stdin (default '-')")
    return parser


def main():
    parser = create_argument_parser()
    args = parser.parse_args()

    with contextlib.ExitStack() as ctx:
        if args.input == Path('-'):
            in_stream, sys.stdin = sys.stdin, None
        else:
            in_stream = open(args.input, 'r', encoding='utf-8')
        ctx.callback(in_stream.close)

        if args.output == Path('-'):
            out_stream, sys.stdout = sys.stdout.detach(), None
        else:
            out_stream = open(args.output, 'wb')
        ctx.callback(out_stream.close)

        socat_stream = SocatStream(stream=in_stream,
                                   with_text=args.with_text)

        pcap_stream = PcapStream(stream=out_stream,
                                 ip_addr_a=args.ip_addr_a,
                                 ip_addr_b=args.ip_addr_b,
                                 tcp_port_a=args.tcp_port_a,
                                 tcp_port_b=args.tcp_port_b)

        while True:
            msg = socat_stream.read()
            if not msg:
                break

            pcap_stream.write(msg)


if __name__ == '__main__':
    sys.argv[0] = 'socat2pcap'
    main()
