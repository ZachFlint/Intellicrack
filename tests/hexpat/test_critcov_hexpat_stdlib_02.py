# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Critical-coverage tests for the second half of the HexPat standard library.

Drives the real preprocessor, lexer, parser, evaluator and ``BuiltinFunctions`` with
small pattern sources and compares the results against values computed
independently with the Python standard library: real files in ``tmp_path`` for
``std::file``, seeded ``random.Random`` instances and the textbook inverse-CDF
formulas for ``std::random``, ``struct`` and ``int.from_bytes`` for
``read_struct_field`` and Python's own format mini-language for ``std::print``.
The ``std::core`` reflection builtins are exercised both wired to the evaluator
and unwired. Handles that the language cannot produce (an unseekable pipe, an
in-memory stream) are placed into the real ``BuiltinFunctions`` handle table.
"""

from __future__ import annotations

import contextlib
import io
import math
import os
import random
import struct
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Any, Literal

import pytest

from intellicrack.core.hexpat.data_reader import DataReader
from intellicrack.core.hexpat.errors import HexPatRuntimeError
from intellicrack.core.hexpat.evaluator import BuiltinCallable, HexPatEvaluator, PatternValue
from intellicrack.core.hexpat.interpreter import HexPatInterpreter
from intellicrack.core.hexpat.lexer import HexPatLexer
from intellicrack.core.hexpat.parser import HexPatParser
from intellicrack.core.hexpat.preprocessor import HexPatPreprocessor
from intellicrack.core.hexpat.stdlib import BuiltinFunctions, set_print_sink
from intellicrack.core.hexpat.type_system import TypeRegistry


if TYPE_CHECKING:
    from collections.abc import Callable, Iterator
    from typing import BinaryIO

    from intellicrack.core.hexpat.ast_nodes import DeclNode, StmtNode


_STRUCT_DATA: bytes = bytes(range(0x10, 0x30))
_TAGGED: str = "[[tag(5)]]\nstruct Tagged {\n    u8 a;\n};\nTagged t @ 0;"
_UNWIRED_MESSAGE: str = "std::core::{name} requires evaluator metadata not yet wired"


@dataclass
class _Rig:
    """A real evaluator wired to a real ``BuiltinFunctions`` the way the interpreter wires it.

    Attributes:
        evaluator: The evaluator that owns the scope the builtins are registered in.
        stdlib: The builtin library bound to the same data reader.
        program: The parsed program that has not necessarily been evaluated yet.
    """

    evaluator: HexPatEvaluator
    stdlib: BuiltinFunctions
    program: list[DeclNode | StmtNode]

    def run(self) -> list[dict[str, Any]]:
        """Evaluate the parsed program.

        Returns:
            list[dict[str, Any]]: The parsed-field dicts produced by the evaluator.
        """
        return self.evaluator.evaluate(self.program)

    def handles(self) -> dict[int, BinaryIO]:
        """Expose the library's open-file table.

        Returns:
            dict[int, BinaryIO]: The live handle table of the builtin library.
        """
        table: dict[int, BinaryIO] = getattr(self.stdlib, "_file_handles")
        return table

    def builtin(self, name: str) -> Callable[..., object]:
        """Look up a registered builtin function in the evaluator scope.

        Args:
            name: The registered builtin name, for example ``std::env``.

        Returns:
            Callable[..., object]: The Python callable behind the builtin.
        """
        entry = self.evaluator.scope.get(name)
        assert entry is not None
        callable_box = entry.value
        assert isinstance(callable_box, BuiltinCallable)
        return callable_box.fn

    def close_handles(self) -> None:
        """Close every file handle still held by the library."""
        table = self.handles()
        for handle in list(table.values()):
            with contextlib.suppress(OSError, ValueError):
                handle.close()
        table.clear()


@pytest.fixture
def make_rig() -> Iterator[Callable[..., _Rig]]:
    """Provide a factory for rigs and close any file handles they still hold afterwards.

    Yields:
        Callable[..., _Rig]: A factory taking the pattern source, optional data
        and a keyword flag choosing whether the reflection provider is wired.
    """
    rigs: list[_Rig] = []

    def _make(source: str, data: bytes | None = None, *, reflection: bool = True) -> _Rig:
        """Build one rig.

        Args:
            source: The pattern source to preprocess, lex and parse.
            data: The bytes the evaluator reads from; 64 zero bytes when omitted.
            reflection: Whether the evaluator's reflection provider is installed.

        Returns:
            _Rig: The wired rig.
        """
        payload = data if data is not None else bytes(64)
        processed, pragma = HexPatPreprocessor().process(source)
        program = HexPatParser(HexPatLexer(processed).tokenize()).parse()
        reader = DataReader.from_bytes(payload)
        evaluator = HexPatEvaluator(reader, TypeRegistry(), pragma)
        stdlib = BuiltinFunctions(reader, pragma)
        stdlib.set_array_index_provider(evaluator.current_array_index)
        stdlib.set_endian_listener(evaluator.set_default_endian)
        if reflection:
            stdlib.set_reflection_provider(evaluator.reflection_provider())
        stdlib.register_all(evaluator.scope)
        rig = _Rig(evaluator=evaluator, stdlib=stdlib, program=program)
        rigs.append(rig)
        return rig

    yield _make
    for rig in rigs:
        rig.close_handles()


@pytest.fixture
def make_broken_writer() -> Iterator[Callable[..., io.BufferedWriter[io.FileIO]]]:
    """Provide a factory for buffered writers over a pipe whose read end is closed.

    Such a writer is unseekable, holds one pending byte, and raises ``OSError``
    from ``tell``, ``seek``, ``truncate``, ``flush`` and ``close``.

    Yields:
        Callable[..., io.BufferedWriter[io.FileIO]]: A factory taking an optional path that
        becomes the ``name`` of the underlying raw file object.
    """
    writers: list[io.BufferedWriter[io.FileIO]] = []

    def _make(name: Path | None = None) -> io.BufferedWriter[io.FileIO]:
        """Build one broken writer.

        Args:
            name: Optional path recorded as the raw file object's ``name``.

        Returns:
            io.BufferedWriter[io.FileIO]: A writer whose flush fails.
        """
        read_fd, write_fd = os.pipe()
        os.close(read_fd)
        raw = io.FileIO(write_fd, "wb")
        if name is not None:
            raw.name = str(name)
        writer = io.BufferedWriter(raw)
        writer.write(b"x")
        writers.append(writer)
        return writer

    yield _make
    for writer in writers:
        with contextlib.suppress(OSError):
            writer.close()


def _field(results: list[dict[str, Any]], name: str) -> dict[str, Any]:
    """Find a parsed-field dict by name.

    Args:
        results: Parsed field dicts produced by the evaluator.
        name: The field name to locate.

    Returns:
        dict[str, Any]: The matching field dict.
    """
    found = next((r for r in results if r["name"] == name), None)
    assert found is not None, f"field '{name}' not in {[r['name'] for r in results]}"
    return found


def _holds(interp: HexPatInterpreter, prelude: str, condition: str, data: bytes | None = None) -> bool:
    """Evaluate a pattern-language condition by placing a probe byte at one of two offsets.

    Args:
        interp: The interpreter used to run the pattern.
        prelude: Pattern source executed before the probe placement.
        condition: A pattern-language expression whose truthiness is observed.
        data: The bytes to evaluate against; 64 zero bytes when omitted.

    Returns:
        bool: True when the condition was truthy (probe placed at offset 3),
        False when it was falsy (probe placed at offset 5).
    """
    payload = data if data is not None else bytes(64)
    results = interp.execute_bytes(f"{prelude}\nu8 probe @ {condition} ? 3 : 5;", payload)
    probe = _field(results, "probe")
    assert probe["offset"] in {3, 5}
    return bool(probe["offset"] == 3)


def _printed(source: str, data: bytes | None = None) -> list[str]:
    """Run a pattern with a print sink installed and return every printed line.

    Args:
        source: The pattern source to execute.
        data: The bytes to evaluate against; 16 zero bytes when omitted.

    Returns:
        list[str]: The strings delivered to the sink, in order.
    """
    sink: list[str] = []
    interpreter = HexPatInterpreter(print_sink=sink.append)
    try:
        interpreter.execute_bytes(source, data if data is not None else bytes(16))
    finally:
        set_print_sink(None)
    return sink


def _lit(path: Path) -> str:
    """Render a path as a forward-slash string that is safe inside a pattern string literal.

    Args:
        path: The filesystem path.

    Returns:
        str: The path with forward slashes.
    """
    return path.as_posix()


def _rng(seed: int) -> random.Random:
    """Build a seeded Mersenne Twister the way the library builds its own.

    Args:
        seed: The seed.

    Returns:
        random.Random: A generator seeded with ``seed``.
    """
    rng_cls: type[random.Random] = vars(random)["Random"]
    return rng_cls(seed)


def _chi_squared(rng: random.Random, degrees: int) -> float:
    """Draw a chi-squared variate as a sum of squared standard normals.

    Args:
        rng: The generator to draw from.
        degrees: The number of squared normals to add.

    Returns:
        float: The sum.
    """
    total = 0.0
    for _ in range(degrees):
        z = rng.gauss(0.0, 1.0)
        total += z * z
    return total


class TestFileSize:
    """``std::file::size``."""

    def test_size_reports_length_and_keeps_position(self, tmp_path: Path) -> None:
        """The size equals the file length and the read position is restored afterwards.

        Args:
            tmp_path: A per-test temporary directory.
        """
        target = tmp_path / "ten.bin"
        target.write_bytes(b"0123456789")
        source = (
            'auto fh = std::file::open("@P@", 1);\n'
            "std::file::seek(fh, 3);\n"
            'std::print("{}", std::file::size(fh));\n'
            'std::print("[{}]", std::file::read(fh, 2));\n'
            "std::file::close(fh);\n"
        ).replace("@P@", _lit(target))
        assert _printed(source) == ["10", "[34]"]

    def test_size_without_arguments_is_integer_zero(self, interp: HexPatInterpreter) -> None:
        """Calling ``size`` with no handle yields the integer zero, not null.

        Args:
            interp: A fresh interpreter.
        """
        assert _holds(interp, "", 'std::core::formatted_value(std::file::size()) == "0x0"') is True

    def test_size_of_unknown_handle_is_an_error(self, interp: HexPatInterpreter) -> None:
        """A handle that was never opened is rejected with its number in the message.

        Args:
            interp: A fresh interpreter.
        """
        with pytest.raises(HexPatRuntimeError) as excinfo:
            interp.execute_bytes("std::file::size(99);", bytes(16))
        assert excinfo.value.message == "std::file: unknown handle 99"

    def test_size_failure_on_unseekable_handle_is_reported(
        self,
        make_rig: Callable[..., _Rig],
        make_broken_writer: Callable[..., io.BufferedWriter[io.FileIO]],
    ) -> None:
        """An ``OSError`` from the stream surfaces as a runtime error naming ``std::file::size``.

        Args:
            make_rig: Factory for wired rigs.
            make_broken_writer: Factory for a pipe-backed writer that cannot seek.
        """
        rig = make_rig("std::file::size(1);")
        rig.handles()[1] = make_broken_writer()
        with pytest.raises(HexPatRuntimeError) as excinfo:
            rig.run()
        assert excinfo.value.message.startswith("std::file::size failed:")


class TestFileResize:
    """``std::file::resize``."""

    def test_resize_truncates_the_file(self, tmp_path: Path) -> None:
        """Shrinking a written file leaves exactly the requested prefix on disk.

        Args:
            tmp_path: A per-test temporary directory.
        """
        target = tmp_path / "resize.bin"
        source = (
            'auto fh = std::file::open("@P@", 3);\n'
            'std::file::write(fh, "hello");\n'
            "std::file::resize(fh, 2);\n"
            'auto rh = std::file::open("@P@", 1);\n'
            'std::print("{}", std::file::size(rh));\n'
            'std::print("[{}]", std::file::read(rh, 10));\n'
            "std::file::close(rh);\n"
            "std::file::close(fh);\n"
        ).replace("@P@", _lit(target))
        assert _printed(source) == ["2", "[he]"]
        assert target.read_bytes() == b"he"

    def test_resize_without_size_is_a_null_no_op(self, tmp_path: Path) -> None:
        """A single argument returns null and leaves the file untouched.

        Args:
            tmp_path: A per-test temporary directory.
        """
        target = tmp_path / "keep.bin"
        target.write_bytes(b"abcd")
        source = (
            'auto fh = std::file::open("@P@", 2);\n'
            'std::print("{}", std::core::formatted_value(std::file::resize(fh)));\n'
            'std::print("{}", std::file::size(fh));\n'
            "std::file::close(fh);\n"
        ).replace("@P@", _lit(target))
        assert _printed(source) == ["null", "4"]
        assert target.read_bytes() == b"abcd"

    def test_resize_of_read_only_handle_is_an_error(self, tmp_path: Path, make_rig: Callable[..., _Rig]) -> None:
        """Truncating a handle opened for reading raises and leaves the file intact.

        Args:
            tmp_path: A per-test temporary directory.
            make_rig: Factory for wired rigs.
        """
        target = tmp_path / "ro.bin"
        target.write_bytes(b"abcd")
        source = f'auto fh = std::file::open("{_lit(target)}", 1);\nstd::file::resize(fh, 0);\n'
        rig = make_rig(source)
        with pytest.raises(HexPatRuntimeError) as excinfo:
            rig.run()
        assert excinfo.value.message.startswith("std::file::resize failed:")
        assert target.read_bytes() == b"abcd"


class TestFileFlush:
    """``std::file::flush``."""

    def test_flush_makes_buffered_writes_visible_to_other_readers(self, tmp_path: Path) -> None:
        """A second handle sees nothing before the flush and the written bytes after it.

        Args:
            tmp_path: A per-test temporary directory.
        """
        target = tmp_path / "flush.bin"
        source = (
            'auto fh = std::file::open("@P@", 3);\n'
            'auto rh = std::file::open("@P@", 1);\n'
            'std::file::write(fh, "ab");\n'
            'std::print("[{}]", std::file::read(rh, 2));\n'
            "std::file::flush(fh);\n"
            'std::print("[{}]", std::file::read(rh, 2));\n'
            "std::file::close(rh);\n"
            "std::file::close(fh);\n"
        ).replace("@P@", _lit(target))
        assert _printed(source) == ["[]", "[ab]"]

    def test_flush_without_handle_returns_null(self, interp: HexPatInterpreter) -> None:
        """Calling ``flush`` with no handle is a null no-op.

        Args:
            interp: A fresh interpreter.
        """
        assert _holds(interp, "", 'std::core::formatted_value(std::file::flush()) == "null"') is True

    def test_flush_failure_is_reported(
        self,
        make_rig: Callable[..., _Rig],
        make_broken_writer: Callable[..., io.BufferedWriter[io.FileIO]],
    ) -> None:
        """A stream whose flush fails raises a runtime error naming ``std::file::flush``.

        Args:
            make_rig: Factory for wired rigs.
            make_broken_writer: Factory for a pipe-backed writer whose flush fails.
        """
        rig = make_rig("std::file::flush(1);")
        rig.handles()[1] = make_broken_writer()
        with pytest.raises(HexPatRuntimeError) as excinfo:
            rig.run()
        assert excinfo.value.message.startswith("std::file::flush failed:")


class TestFileRemove:
    """``std::file::remove``."""

    def test_remove_deletes_the_file_from_disk(self, tmp_path: Path) -> None:
        """Removing a handle closes it and deletes the file it was opened on.

        Args:
            tmp_path: A per-test temporary directory.
        """
        target = tmp_path / "gone.bin"
        source = f'auto fh = std::file::open("{_lit(target)}", 3);\nstd::file::write(fh, "x");\nstd::file::remove(fh);\n'
        _printed(source)
        assert not target.exists()

    def test_removed_handle_is_no_longer_usable(self, tmp_path: Path, interp: HexPatInterpreter) -> None:
        """After removal the handle number is unknown to every other file builtin.

        Args:
            tmp_path: A per-test temporary directory.
            interp: A fresh interpreter.
        """
        target = tmp_path / "once.bin"
        source = f'auto fh = std::file::open("{_lit(target)}", 3);\nstd::file::remove(fh);\nstd::file::size(fh);\n'
        with pytest.raises(HexPatRuntimeError) as excinfo:
            interp.execute_bytes(source, bytes(16))
        assert excinfo.value.message.startswith("std::file: unknown handle")
        assert not target.exists()

    def test_remove_without_handle_returns_null(self, interp: HexPatInterpreter) -> None:
        """Calling ``remove`` with no handle is a null no-op.

        Args:
            interp: A fresh interpreter.
        """
        assert _holds(interp, "", 'std::core::formatted_value(std::file::remove()) == "null"') is True

    def test_remove_of_nameless_stream_only_closes_it(self, make_rig: Callable[..., _Rig]) -> None:
        """A stream without a file name is closed and forgotten without touching the filesystem.

        Args:
            make_rig: Factory for wired rigs.
        """
        rig = make_rig("std::file::remove(1);")
        stream = io.BytesIO(b"abc")
        rig.handles()[1] = stream
        rig.run()
        assert stream.closed
        assert 1 not in rig.handles()

    def test_remove_survives_close_failure_and_still_deletes(
        self,
        tmp_path: Path,
        make_rig: Callable[..., _Rig],
        make_broken_writer: Callable[..., io.BufferedWriter[io.FileIO]],
    ) -> None:
        """A failing ``close`` is tolerated and the named file is still deleted.

        Args:
            tmp_path: A per-test temporary directory.
            make_rig: Factory for wired rigs.
            make_broken_writer: Factory for a pipe-backed writer whose close fails.
        """
        victim = tmp_path / "victim.bin"
        victim.write_bytes(b"data")
        rig = make_rig("std::file::remove(1);")
        rig.handles()[1] = make_broken_writer(victim)
        rig.run()
        assert not victim.exists()
        assert 1 not in rig.handles()

    def test_remove_reports_failure_to_delete(self, tmp_path: Path, interp: HexPatInterpreter) -> None:
        """A file that another open handle pins cannot be deleted and the error says so.

        Args:
            tmp_path: A per-test temporary directory.
            interp: A fresh interpreter.
        """
        target = tmp_path / "pinned.bin"
        target.write_bytes(b"data")
        source = f'auto fh = std::file::open("{_lit(target)}", 1);\nstd::file::remove(fh);\n'
        with target.open("rb"), pytest.raises(HexPatRuntimeError) as excinfo:
            interp.execute_bytes(source, bytes(16))
        assert excinfo.value.message.startswith("std::file::remove failed:")
        assert target.read_bytes() == b"data"


class TestFileCreateDirectories:
    """``std::file::create_directories``."""

    def test_creates_nested_directories_and_is_idempotent(self, tmp_path: Path) -> None:
        """A deep absolute path is created, and creating it again is not an error.

        Args:
            tmp_path: A per-test temporary directory.
        """
        target = tmp_path / "a" / "b" / "c"
        source = f'std::file::create_directories("{_lit(target)}");\nstd::file::create_directories("{_lit(target)}");\n'
        _printed(source)
        assert target.is_dir()

    def test_relative_path_is_rejected(self, interp: HexPatInterpreter) -> None:
        """A relative path is refused and nothing is created in the working directory.

        Args:
            interp: A fresh interpreter.
        """
        with pytest.raises(HexPatRuntimeError) as excinfo:
            interp.execute_bytes('std::file::create_directories("critcov_relative_dir/nested");', bytes(16))
        assert excinfo.value.message == "std::file::create_directories requires an absolute path, got 'critcov_relative_dir/nested'"
        assert not Path("critcov_relative_dir").exists()

    def test_without_arguments_returns_null(self, interp: HexPatInterpreter) -> None:
        """Calling ``create_directories`` with no path is a null no-op.

        Args:
            interp: A fresh interpreter.
        """
        assert _holds(interp, "", 'std::core::formatted_value(std::file::create_directories()) == "null"') is True

    def test_existing_file_blocks_creation(self, tmp_path: Path, interp: HexPatInterpreter) -> None:
        """A path that already names a regular file cannot become a directory.

        Args:
            tmp_path: A per-test temporary directory.
            interp: A fresh interpreter.
        """
        blocker = tmp_path / "blocker"
        blocker.write_bytes(b"x")
        with pytest.raises(HexPatRuntimeError) as excinfo:
            interp.execute_bytes(f'std::file::create_directories("{_lit(blocker)}");', bytes(16))
        assert excinfo.value.message.startswith("std::file::create_directories failed:")
        assert blocker.is_file()


_DRAWS: list[tuple[str, Callable[[random.Random], float]]] = [
    ("0, 1, 6", lambda r: r.randint(1, 6)),
    ("0, 7, 3", lambda r: r.randint(7, 7)),
    ("1, 10.0, 2.5", lambda r: r.gauss(10.0, 2.5)),
    ("2, 0.5", lambda r: r.expovariate(0.5)),
    ("3, 2.0, 1.5", lambda r: r.gammavariate(2.0, 1.5)),
    ("4, 1.5, 2.0", lambda r: r.weibullvariate(1.5, 2.0)),
    ("5, 3.0, 2.0", lambda r: 3.0 - 2.0 * math.log(-math.log(max(r.random(), 1e-300)))),
    ("6, 3", lambda r: _chi_squared(r, 3)),
    ("6, 2.9", lambda r: _chi_squared(r, 2)),
    ("7, 1.0, 0.5", lambda r: 1.0 + 0.5 * math.tan(math.pi * (r.random() - 0.5))),
    ("10, 0.0, 0.5", lambda r: math.exp(r.gauss(0.0, 0.5))),
    ("11, 1.0", lambda _r: 1),
    ("11, 0.0", lambda _r: 0),
    ("11, 0.5", lambda r: 1 if r.random() < 0.5 else 0),
    ("14, 0.5", lambda r: math.floor(math.log(max(r.random(), 1e-300)) / math.log(1.0 - 0.5))),
]
_DRAW_IDS: list[str] = [
    "uniform",
    "uniform-reversed-bounds",
    "normal",
    "exponential",
    "gamma",
    "weibull",
    "extreme-value",
    "chi-squared",
    "chi-squared-fractional-degrees",
    "cauchy",
    "log-normal",
    "bernoulli-always",
    "bernoulli-never",
    "bernoulli-half",
    "geometric",
]


class TestRandom:
    """``std::random::set_seed`` and ``std::random::generate``."""

    def test_same_seed_repeats_the_mersenne_twister_sequence(self) -> None:
        """Seeding with the same value restarts the sequence a seeded ``random.Random`` produces."""
        source = (
            "std::random::set_seed(42);\n"
            'std::print("{}", std::random::generate(0, 0, 1000000));\n'
            'std::print("{}", std::random::generate(0, 0, 1000000));\n'
            "std::random::set_seed(42);\n"
            'std::print("{}", std::random::generate(0, 0, 1000000));\n'
        )
        reference = _rng(42)
        first = str(reference.randint(0, 1000000))
        second = str(reference.randint(0, 1000000))
        assert _printed(source) == [first, second, first]

    def test_set_seed_returns_null_and_reseeding_without_argument_breaks_determinism(self) -> None:
        """``set_seed`` yields null, and a bare ``set_seed()`` discards the previous seed."""
        top = 0x1FFFFFFFFFFFFF
        source = (
            'std::print("{}", std::core::formatted_value(std::random::set_seed(7)));\n'
            'std::print("{}", std::core::formatted_value(std::random::set_seed()));\n'
            f'std::print("{{}}", std::random::generate(0, 0, {top}));\n'
        )
        printed = _printed(source)
        assert printed[:2] == ["null", "null"]
        assert int(printed[2]) != _rng(7).randint(0, top)

    @pytest.mark.parametrize(("arguments", "expected"), _DRAWS, ids=_DRAW_IDS)
    def test_generate_matches_independent_distribution_draw(self, arguments: str, expected: Callable[[random.Random], float]) -> None:
        """Each distribution tag reproduces the textbook draw from an identically seeded generator.

        Args:
            arguments: The ``generate`` argument list as pattern source.
            expected: Computes the independent expectation from a seeded generator.
        """
        source = f'std::random::set_seed(12345);\nstd::print("{{}}", std::random::generate({arguments}));\n'
        printed = _printed(source)
        assert len(printed) == 1
        assert float(printed[0]) == pytest.approx(float(expected(_rng(12345))), rel=1e-12)

    def test_generate_without_arguments_is_integer_zero(self, interp: HexPatInterpreter) -> None:
        """Calling ``generate`` with no distribution yields the integer zero, not null.

        Args:
            interp: A fresh interpreter.
        """
        assert _holds(interp, "", 'std::core::formatted_value(std::random::generate()) == "0x0"') is True

    @pytest.mark.parametrize(
        ("arguments", "message"),
        [
            ("2, 0", "std::random exponential lambda must be positive"),
            ("2, -1.5", "std::random exponential lambda must be positive"),
            ("3, 0.0, 1.0", "std::random gamma parameters must be positive"),
            ("3, 1.0, 0.0", "std::random gamma parameters must be positive"),
            ("4, 0.0, 1.0", "std::random weibull parameters must be positive"),
            ("4, 1.0, -2.0", "std::random weibull parameters must be positive"),
            ("6, 0", "std::random chi-squared n must be positive"),
            ("6, -3", "std::random chi-squared n must be positive"),
            ("14, 0.0", "std::random geometric probability must be in (0, 1)"),
            ("14, 1.0", "std::random geometric probability must be in (0, 1)"),
            ("14, 1.5", "std::random geometric probability must be in (0, 1)"),
            ("8", "std::random unsupported distribution tag 8"),
            ("9", "std::random unsupported distribution tag 9"),
            ("12", "std::random unsupported distribution tag 12"),
            ("99", "std::random unsupported distribution tag 99"),
        ],
    )
    def test_generate_rejects_invalid_parameters_and_unknown_tags(self, interp: HexPatInterpreter, arguments: str, message: str) -> None:
        """Out-of-domain parameters and unsupported distribution tags are runtime errors.

        Args:
            interp: A fresh interpreter.
            arguments: The ``generate`` argument list as pattern source.
            message: The expected error message.
        """
        with pytest.raises(HexPatRuntimeError) as excinfo:
            interp.execute_bytes(f"std::random::generate({arguments});", bytes(16))
        assert excinfo.value.message == message


class TestEnvironmentAndPacks:
    """``std::env``, ``std::sizeof_pack`` and ``std::core::set_endian``."""

    def test_env_reads_named_variable_and_defaults_to_empty(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """A set variable returns its value; an unset one and a missing name return an empty string.

        Args:
            monkeypatch: Pytest's environment patcher.
        """
        monkeypatch.setenv("HEXPAT_CRITCOV_ENV_VALUE", "alpha beta")
        monkeypatch.delenv("HEXPAT_CRITCOV_ENV_MISSING", raising=False)
        source = (
            'std::print("[{}]", std::env("HEXPAT_CRITCOV_ENV_VALUE"));\n'
            'std::print("[{}]", std::env("HEXPAT_CRITCOV_ENV_MISSING"));\n'
            'std::print("[{}]", std::env());\n'
        )
        assert _printed(source) == ["[alpha beta]", "[]", "[]"]

    def test_env_stringifies_a_numeric_pattern_argument(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """A non-string pattern value is converted to text before the lookup.

        Args:
            monkeypatch: Pytest's environment patcher.
        """
        monkeypatch.setenv("1234", "numeric-name")
        assert _printed('std::print("[{}]", std::env(1234));') == ["[numeric-name]"]

    def test_env_accepts_unwrapped_arguments(self, monkeypatch: pytest.MonkeyPatch, make_rig: Callable[..., _Rig]) -> None:
        """Raw strings, raw numbers and no argument at all resolve as the pattern forms do.

        Args:
            monkeypatch: Pytest's environment patcher.
            make_rig: Factory for wired rigs.
        """
        monkeypatch.setenv("HEXPAT_CRITCOV_ENV_VALUE", "alpha beta")
        monkeypatch.setenv("1234", "numeric-name")
        env = make_rig("").builtin("std::env")
        by_string = env("HEXPAT_CRITCOV_ENV_VALUE")
        by_number = env(1234)
        by_nothing = env()
        assert isinstance(by_string, PatternValue)
        assert isinstance(by_number, PatternValue)
        assert isinstance(by_nothing, PatternValue)
        assert by_string.value == "alpha beta"
        assert by_number.value == "numeric-name"
        assert repr(by_nothing.value) == "''"

    def test_sizeof_pack_counts_its_arguments(self) -> None:
        """The pack size is the number of arguments, including none."""
        assert _printed('std::print("{}|{}", std::sizeof_pack(10, 20, 30), std::sizeof_pack());') == ["3|0"]

    def test_set_endian_without_argument_keeps_the_current_endian(self, interp: HexPatInterpreter) -> None:
        """A bare ``set_endian()`` changes nothing, so a previous big-endian choice stays in force.

        Args:
            interp: A fresh interpreter.
        """
        data = bytes([0x12, 0x34]) + bytes(14)
        source = "std::core::set_endian(1);\nstd::core::set_endian();\nu16 v @ 0;"
        value = _field(interp.execute_bytes(source, data), "v")
        assert value["display_value"] == f"0x{struct.unpack_from('>H', data)[0]:X}"
        assert value["display_value"] != f"0x{struct.unpack_from('<H', data)[0]:X}"
        assert _printed("std::core::set_endian(1);\nstd::core::set_endian();\n" + 'std::print("{}", std::core::get_endian());') == ["1"]


class TestReflectionWired:
    """The ``std::core`` reflection builtins backed by the evaluator's provider."""

    @pytest.mark.parametrize(
        "condition",
        [
            'std::core::has_attribute(t, "tag")',
            'std::core::get_attribute_argument(t, "tag") == 5',
            'std::core::get_attribute_argument(t, "tag", 0) == 5',
        ],
        ids=["has", "argument-default-index", "argument-explicit-index"],
    )
    def test_attribute_queries_hold_for_the_annotated_struct(self, interp: HexPatInterpreter, condition: str) -> None:
        """Attribute presence and argument values come from the annotations on the placed struct.

        Args:
            interp: A fresh interpreter.
            condition: A condition that must hold after placing the annotated struct.
        """
        assert _holds(interp, _TAGGED, condition) is True

    @pytest.mark.parametrize(
        "condition",
        [
            'std::core::has_attribute(t, "absent")',
            "std::core::has_attribute(t)",
            'std::core::get_attribute_argument(t, "tag") == 6',
        ],
        ids=["has-not", "has-one-argument", "argument-value-differs"],
    )
    def test_attribute_queries_fail_for_other_names_and_values(self, interp: HexPatInterpreter, condition: str) -> None:
        """Unknown attributes, a missing attribute name and a wrong argument value do not hold.

        Args:
            interp: A fresh interpreter.
            condition: A condition that must not hold after placing the annotated struct.
        """
        assert _holds(interp, _TAGGED, condition) is False

    @pytest.mark.parametrize(
        ("call", "message"),
        [
            ("std::core::get_attribute_argument(t)", "std::core::get_attribute_argument requires (pattern, attribute, [index])"),
            ("std::core::get_attribute_argument()", "std::core::get_attribute_argument requires (pattern, attribute, [index])"),
            ('std::core::get_attribute_argument(t, "tag", 1)', "std::core::get_attribute_argument: index 1 out of range"),
        ],
        ids=["one-argument", "no-argument", "index-forwarded"],
    )
    def test_attribute_argument_errors(self, interp: HexPatInterpreter, call: str, message: str) -> None:
        """Too few arguments and an out-of-range index are runtime errors.

        Args:
            interp: A fresh interpreter.
            call: The offending call as pattern source.
            message: The expected error message.
        """
        with pytest.raises(HexPatRuntimeError) as excinfo:
            interp.execute_bytes(f"{_TAGGED}\n{call};", bytes(16))
        assert excinfo.value.message == message

    @pytest.mark.parametrize(
        "condition",
        [
            "std::core::member_count() == 0",
            "std::core::member_count(v) == 0",
            '!std::core::has_member(v, "x")',
            "!std::core::has_member(v)",
            "!std::core::has_attribute(v)",
            'std::core::formatted_value() == ""',
            'std::core::formatted_value((u8)(171)) == "0xAB"',
            'std::core::formatted_value((s8)(200)) == "-56"',
            "!std::core::is_valid_enum()",
            'std::core::formatted_value(std::core::execute_function()) == "null"',
            'std::core::formatted_value(std::core::set_pattern_color(v)) == "null"',
            'std::core::formatted_value(std::core::set_display_name(v)) == "null"',
            'std::core::formatted_value(std::core::set_pattern_comment(v)) == "null"',
        ],
    )
    def test_plain_values_and_missing_arguments(self, interp: HexPatInterpreter, condition: str) -> None:
        """Scalars carry no members, and calls without enough arguments degrade to neutral results.

        Args:
            interp: A fresh interpreter.
            condition: A condition that must hold.
        """
        assert _holds(interp, "u8 v @ 0;", condition) is True

    def test_is_valid_enum_follows_declared_members(self, interp: HexPatInterpreter) -> None:
        """An enum field is valid exactly when its value is one of the declared members.

        Args:
            interp: A fresh interpreter.
        """
        prelude = "enum Color : u8 {\n    Red = 1,\n    Green = 2\n};\nColor good @ 0;\nColor bad @ 1;"
        data = bytes([2, 7]) + bytes(14)
        assert _holds(interp, prelude, "std::core::is_valid_enum(good)", data) is True
        assert _holds(interp, prelude, "std::core::is_valid_enum(bad)", data) is False

    def test_short_setter_calls_record_nothing(self, make_rig: Callable[..., _Rig]) -> None:
        """Color, name and comment setters called without a value leave no override behind.

        Args:
            make_rig: Factory for wired rigs.
        """
        source = "u8 v @ 0;\nstd::core::set_pattern_color(v);\nstd::core::set_display_name(v);\nstd::core::set_pattern_comment(v);"
        rig = make_rig(source)
        rig.run()
        overrides: dict[int, dict[str, object]] = getattr(rig.evaluator, "_reflection_overrides")
        assert overrides == {}

    def test_palette_rotates_through_installed_colors(self, interp: HexPatInterpreter) -> None:
        """Installed palette entries are masked to 32 bits and cycle across placements.

        Args:
            interp: A fresh interpreter.
        """
        source = "std::core::set_pattern_palette_colors(0x55667788, 0x1DEADBEEF);\nu8 a @ 0;\nu8 b @ 1;\nu8 c @ 2;"
        results = interp.execute_bytes(source, bytes(8))
        assert [r["color"] for r in results] == ["#55667788", "#DEADBEEF", "#55667788"]

    def test_reset_palette_restarts_the_default_rotation(self, interp: HexPatInterpreter) -> None:
        """Resetting drops the custom palette and restarts the default colors from the first entry.

        Args:
            interp: A fresh interpreter.
        """
        source = "std::core::set_pattern_palette_colors(0x55667788);\nu8 a @ 0;\nstd::core::reset_pattern_palette();\nu8 b @ 1;\nu8 c @ 2;"
        results = interp.execute_bytes(source, bytes(8))
        assert [r["color"] for r in results] == ["#55667788", HexPatEvaluator.FIELD_COLORS[0], HexPatEvaluator.FIELD_COLORS[1]]

    def test_execute_function_forwards_every_argument(self, interp: HexPatInterpreter) -> None:
        """A declared function is called by name with all following arguments.

        Args:
            interp: A fresh interpreter.
        """
        prelude = "fn add(u32 a, u32 b) {\n    return a + b;\n}"
        assert _holds(interp, prelude, 'std::core::execute_function("add", 3, 4) == 7') is True
        assert _holds(interp, prelude, 'std::core::execute_function("add", 3, 4) == 8') is False

    def test_execute_function_wraps_unwrapped_arguments(self, make_rig: Callable[..., _Rig]) -> None:
        """Raw Python numbers handed to ``execute_function`` reach the callee as pattern values.

        Args:
            make_rig: Factory for wired rigs.
        """
        rig = make_rig("fn twice(u32 x) {\n    return x * 2;\n}")
        rig.run()
        result = rig.builtin("std::core::execute_function")("twice", 4)
        assert isinstance(result, PatternValue)
        assert result.value == 8

    @pytest.mark.parametrize(
        ("name", "extra"),
        [
            ("member_count", ()),
            ("has_member", ("x",)),
            ("formatted_value", ()),
            ("is_valid_enum", ()),
            ("has_attribute", ("x",)),
            ("get_attribute_argument", ("x",)),
            ("set_pattern_color", (1,)),
            ("set_display_name", ("n",)),
            ("set_pattern_comment", ("c",)),
        ],
    )
    def test_reflection_requires_a_pattern_argument(self, make_rig: Callable[..., _Rig], name: str, extra: tuple[object, ...]) -> None:
        """A first argument that is not a pattern value is rejected by name.

        Args:
            make_rig: Factory for wired rigs.
            name: The ``std::core`` builtin under test.
            extra: The arguments following the pattern.
        """
        builtin = make_rig("").builtin(f"std::core::{name}")
        with pytest.raises(HexPatRuntimeError) as excinfo:
            builtin("not a pattern", *extra)
        assert excinfo.value.message == f"std::core::{name} requires a pattern argument"


class TestReflectionUnwired:
    """The ``std::core`` reflection builtins when no evaluator provider is installed."""

    @pytest.mark.parametrize(
        ("name", "extra"),
        [
            ("has_attribute", ("x",)),
            ("get_attribute_argument", ("x",)),
            ("member_count", ()),
            ("has_member", ("x",)),
            ("formatted_value", ()),
            ("is_valid_enum", ()),
            ("set_pattern_color", (1,)),
            ("set_display_name", ("n",)),
            ("set_pattern_comment", ("c",)),
        ],
    )
    def test_unwired_pattern_builtins_fail_loudly(self, make_rig: Callable[..., _Rig], name: str, extra: tuple[object, ...]) -> None:
        """Without a provider every pattern-taking reflection builtin raises instead of answering.

        Args:
            make_rig: Factory for wired rigs.
            name: The ``std::core`` builtin under test.
            extra: The arguments following the pattern.
        """
        builtin = make_rig("", reflection=False).builtin(f"std::core::{name}")
        with pytest.raises(HexPatRuntimeError) as excinfo:
            builtin(PatternValue(value=1), *extra)
        assert excinfo.value.message == _UNWIRED_MESSAGE.format(name=name)

    @pytest.mark.parametrize(
        ("name", "arguments"),
        [
            ("set_pattern_palette_colors", (1, 2)),
            ("reset_pattern_palette", ()),
            ("execute_function", ("f",)),
        ],
    )
    def test_unwired_palette_and_dispatch_builtins_fail_loudly(
        self,
        make_rig: Callable[..., _Rig],
        name: str,
        arguments: tuple[object, ...],
    ) -> None:
        """Without a provider the palette and function-dispatch builtins raise instead of answering.

        Args:
            make_rig: Factory for wired rigs.
            name: The ``std::core`` builtin under test.
            arguments: The arguments passed to it.
        """
        builtin = make_rig("", reflection=False).builtin(f"std::core::{name}")
        with pytest.raises(HexPatRuntimeError) as excinfo:
            builtin(*arguments)
        assert excinfo.value.message == _UNWIRED_MESSAGE.format(name=name)


class TestPrintWarningError:
    """``std::print``, ``std::warning`` and ``std::error`` without or with arguments."""

    def test_print_without_arguments_sends_an_empty_line(self) -> None:
        """A bare ``print()`` delivers an empty string to the sink."""
        assert _printed("std::print();") == [""]

    def test_print_and_warning_without_sink_still_return(self) -> None:
        """With no sink installed both calls complete and evaluation continues."""
        results = HexPatInterpreter().execute_bytes('std::print();\nstd::warning("careful");\nu8 a @ 0;', bytes(4))
        assert [r["name"] for r in results] == ["a"]

    def test_warning_reaches_the_sink_with_a_prefix(self) -> None:
        """A warning is forwarded with a ``warning: `` prefix, also when the message is missing."""
        assert _printed('std::warning("careful");\nstd::warning();') == ["warning: careful", "warning: "]

    def test_error_raises_with_the_given_message(self, interp: HexPatInterpreter) -> None:
        """``error`` aborts evaluation with exactly the supplied message.

        Args:
            interp: A fresh interpreter.
        """
        with pytest.raises(HexPatRuntimeError) as excinfo:
            interp.execute_bytes('std::error("boom");', bytes(4))
        assert excinfo.value.message == "boom"

    def test_error_without_message_raises_an_empty_message(self, interp: HexPatInterpreter) -> None:
        """A bare ``error()`` still aborts, with an empty message.

        Args:
            interp: A fresh interpreter.
        """
        with pytest.raises(HexPatRuntimeError) as excinfo:
            interp.execute_bytes("std::error();", bytes(4))
        assert repr(excinfo.value.message) == "''"


class TestFormatString:
    """The ``{}`` field expansion behind ``std::print`` and ``std::format``."""

    @pytest.mark.parametrize(
        ("template", "arguments", "expected"),
        [
            ("{} {0} {}", "10, 20", "10 10 20"),
            ("[{3}]{}", "1", "[]1"),
            ("[{-1}]", "5", "[]"),
            ("{abc}-{}", "7", "{abc}-7"),
            ("{1x:5}", "7", "{1x:5}"),
            ("{:08X}", "0xCAFE", "0000CAFE"),
            ("{1:>4}|{0:<3}|", '"a", "b"', "   b|a  |"),
            ("{:.2f}", "3.14159", "3.14"),
            ("{:d}|{:d}", '"text", 2.5', "text|2.5"),
        ],
        ids=[
            "explicit-and-automatic-indexes",
            "index-past-the-end",
            "negative-index",
            "non-numeric-index-kept-verbatim",
            "non-numeric-index-with-spec-kept-verbatim",
            "hex-spec",
            "alignment-spec",
            "float-spec",
            "unusable-spec-falls-back-to-plain-text",
        ],
    )
    def test_fields_expand_like_python_format(self, template: str, arguments: str, expected: str) -> None:
        """Indexes, specs and malformed fields render as the format mini-language dictates.

        Args:
            template: The format string.
            arguments: The values following the template, as pattern source.
            expected: The rendered text.
        """
        assert _printed(f'std::print("{template}", {arguments});') == [expected]


class TestReadStructField:
    """``std::mem::read_struct_field``."""

    @pytest.mark.parametrize(
        ("offset", "size", "code"),
        [(0, 1, "B"), (3, 2, "H"), (5, 4, "I"), (9, 8, "Q")],
        ids=["u8", "u16", "u32", "u64"],
    )
    @pytest.mark.parametrize(("prelude", "prefix"), [("", "<"), ("std::core::set_endian(1);\n", ">")], ids=["little", "big"])
    def test_narrow_fields_decode_in_the_active_byte_order(self, prelude: str, prefix: str, offset: int, size: int, code: str) -> None:
        """Fields of 1, 2, 4 and 8 bytes decode as ``struct`` unpacks them in the active endian.

        Args:
            prelude: Pattern source that selects the byte order.
            prefix: The matching ``struct`` byte-order prefix.
            offset: The field offset.
            size: The field size in bytes.
            code: The ``struct`` format character of that size.
        """
        expected = struct.unpack_from(f"{prefix}{code}", _STRUCT_DATA, offset)[0]
        printed = _printed(f'{prelude}std::print("{{}}", std::mem::read_struct_field({offset}, {size}));', _STRUCT_DATA)
        assert printed == [str(expected)]

    @pytest.mark.parametrize(
        ("prelude", "byteorder"),
        [("", "little"), ("std::core::set_endian(1);\n", "big")],
        ids=["little", "big"],
    )
    @pytest.mark.parametrize("size", [12, 16], ids=["twelve-bytes", "sixteen-bytes"])
    def test_wide_fields_decode_as_one_unsigned_integer(self, prelude: str, byteorder: Literal["little", "big"], size: int) -> None:
        """Fields wider than 8 bytes decode as a single unsigned integer in the active endian.

        Args:
            prelude: Pattern source that selects the byte order.
            byteorder: The matching ``int.from_bytes`` byte order.
            size: The field size in bytes.
        """
        expected = int.from_bytes(_STRUCT_DATA[2 : 2 + size], byteorder)
        printed = _printed(f'{prelude}std::print("{{}}", std::mem::read_struct_field(2, {size}));', _STRUCT_DATA)
        assert printed == [str(expected)]

    def test_missing_arguments_default_to_offset_zero_and_four_bytes(self) -> None:
        """No arguments read a u32 at offset 0, and a lone offset reads a u32 there."""
        source = 'std::print("{}", std::mem::read_struct_field());\nstd::print("{}", std::mem::read_struct_field(8));'
        expected = [str(struct.unpack_from("<I", _STRUCT_DATA, 0)[0]), str(struct.unpack_from("<I", _STRUCT_DATA, 8)[0])]
        assert _printed(source, _STRUCT_DATA) == expected

    @pytest.mark.parametrize("size", [3, 5, 6, 7])
    def test_odd_sized_fields_decode_as_unsigned_little_endian(self, size: int) -> None:
        """A field of 3, 5, 6 or 7 bytes decodes as the unsigned integer of exactly those bytes.

        Args:
            size: The field size in bytes.
        """
        expected = int.from_bytes(_STRUCT_DATA[1 : 1 + size], "little")
        printed = _printed(f'std::print("{{}}", std::mem::read_struct_field(1, {size}));', _STRUCT_DATA)
        assert printed == [str(expected)]
