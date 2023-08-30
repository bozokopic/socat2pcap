import datetime
import io

from socat2pcap import common


class SocatStream:

    def __init__(self,
                 stream: io.TextIOBase,
                 with_text: bool):
        self._stream = stream
        self._with_text = with_text

    def read(self) -> common.Msg | None:
        line = self._stream.readline()
        if not line:
            return

        direction = common.Direction(line[0])
        timestamp = datetime.datetime(year=int(line[2:6]),
                                      month=int(line[7:9]),
                                      day=int(line[10:12]),
                                      hour=int(line[13:15]),
                                      minute=int(line[16:18]),
                                      second=int(line[19:21]),
                                      microsecond=int(line[22:28])).timestamp()

        if not self._with_text:
            line = self._stream.readline()
            if not line:
                return

            data = bytes.fromhex(line)

        else:
            data = b''
            while True:
                line = self._stream.readline()
                if not line:
                    return

                if line.startswith('--'):
                    break

                data += bytes.fromhex(line[:48])

        return common.Msg(direction=direction,
                          timestamp=timestamp,
                          data=data)
