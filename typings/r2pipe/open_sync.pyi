from r2pipe.open_base import OpenBase

class open(OpenBase):
    def __init__(
        self,
        filename: str = ...,
        flags: list[str] = ...,
        radare2home: str | None = ...,
    ) -> None: ...
    def __enter__(self) -> open: ...
    def __exit__(self, *args: object) -> None: ...
