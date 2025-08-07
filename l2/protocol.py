from struct import pack, unpack
from uuid import uuid4, UUID


class Payload:
    def __init__(
        self,
        uuid: UUID | None = None,
        msg: str = "",
    ):
        self.msg = msg
        self.uuid = uuid or uuid4()

    def __repr__(self):
        return f"{self.uuid} @ {self.msg}"

    @classmethod
    def from_bytes(cls, raw: bytes):
        return cls(
            uuid=UUID(bytes=raw[:16]),
            msg=raw[16:].decode("utf-8"),
        )

    @property
    def bytes(self):
        return self.uuid.bytes + self.msg.encode()

