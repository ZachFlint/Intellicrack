from subprocess import (
    DEVNULL as DEVNULL,
    PIPE as PIPE,
    STARTUPINFO as STARTUPINFO,
    CalledProcessError as CalledProcessError,
    CompletedProcess as CompletedProcess,
    Popen as Popen,
    SubprocessError as SubprocessError,
    TimeoutExpired as TimeoutExpired,
    run as run,
)

CREATE_NEW_CONSOLE: int
CREATE_NEW_PROCESS_GROUP: int
CREATE_NO_WINDOW: int
STARTF_USESHOWWINDOW: int
