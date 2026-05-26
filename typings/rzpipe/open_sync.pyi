from rzpipe.open_base import OpenBase

class open(OpenBase):
    def __init__(
        self,
        filename: str = ...,
        flags: list[str] | None = ...,
        rizin_home: str | None = ...,
        **kwargs: object,
    ) -> None: ...
    def __enter__(self) -> open: ...
    def __exit__(self, *args: object) -> None: ...
