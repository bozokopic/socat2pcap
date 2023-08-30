import enum
import typing


class Direction(enum.Enum):
    A_TO_B = '>'
    B_TO_A = '<'


class Msg(typing.NamedTuple):
    direction: Direction
    timestamp: float
    data: bytes


def invert_direction(direction: Direction) -> Direction:
    if direction == Direction.A_TO_B:
        return Direction.B_TO_A

    if direction == Direction.B_TO_A:
        return Direction.A_TO_B

    raise ValueError('unsupported direction')
