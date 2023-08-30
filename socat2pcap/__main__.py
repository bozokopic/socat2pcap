import sys

from socat2pcap.main import main


if __name__ == '__main__':
    sys.argv[0] = 'socat2pcap'
    main()
