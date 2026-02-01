from r2pipe.open_base import OpenBase

class open(OpenBase):
    def __init__(
        self,
        filename: str = ...,
        flags: list[str] = ...,
        radare2home: str | None = ...,
    ) -> None: ...
