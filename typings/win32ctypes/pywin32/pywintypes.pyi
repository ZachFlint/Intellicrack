class error(Exception):
    winerror: int
    funcname: str
    strerror: str

    def __init__(self, winerror: int = ..., funcname: str = ..., strerror: str = ...) -> None: ...
