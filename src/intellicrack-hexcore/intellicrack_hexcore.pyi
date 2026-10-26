# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

from typing import Any

class Bookmark:
    """A labeled, colored byte range pinned in a document.

    A document stores copies of the bookmarks passed to it, so changing a ``Bookmark`` after adding it does not change the
    document; use ``HexDocument.update_bookmark`` instead.

    Args:
        offset: First byte of the range.
        length: Number of bytes in the range.
        label: User-visible name.
        color: Display color, as the UI's color string.

    Attributes:
        offset: First byte of the range.
        length: Number of bytes in the range.
        label: User-visible name.
        color: Display color, as the UI's color string.
    """

    offset: int
    length: int
    label: str
    color: str

    def __init__(self, offset: int, length: int, label: str, color: str) -> None: ...

class HexDocument:
    """An editable byte document with undo history, bookmarks, templates and analysis.

    A document starts empty, is opened from a file, is built from bytes, or is copied from another process's memory. Its
    bytes live in a piece table over the original data, and every content edit is recorded in an undo history. The
    document also holds bookmarks, structure templates and virtual-address mappings, none of which are part of the undo
    history. One document can be shared across Python threads: each call takes an internal reader-writer lock, and long
    operations run with the GIL released.
    """

    def __init__(self) -> None: ...
    @staticmethod
    def open(path: str) -> HexDocument:
        """Open the file at ``path`` as a new document.

        The path is stored in absolute form. On Windows the file is mapped read-only and locked against other writers;
        an empty file, a file another handle can already write, and every file on other platforms are copied into memory
        instead. Raises ``OSError`` when the path is not a regular file or cannot be opened, mapped or read.

        Args:
            path: Path of the file to open.

        Returns:
            HexDocument: The opened document, unmodified and with an empty undo history.
        """
    @staticmethod
    def open_bytes(data: bytes) -> HexDocument:
        """Create an in-memory document over a copy of ``data``, with no file path.

        Args:
            data: Initial contents of the document.

        Returns:
            HexDocument: The new document, unmodified and with an empty undo history.
        """
    def save(self, path: str) -> None:
        """Save the document to ``path`` and adopt that file as the document's own.

        The bytes are written to a temporary file beside ``path``, flushed, and renamed over ``path``, so the file holds
        either its old contents or the new ones. On success the document maps the saved file (or keeps the bytes in
        memory when it cannot), ``file_path`` reports the new path, and the current undo position becomes the saved
        state. The GIL is released for the whole save. Raises ``OSError`` when writing, flushing or renaming fails,
        including when another program has ``path`` open for writing on Windows.

        Args:
            path: Destination file path.
        """
    def save_as(self, path: str) -> None:
        """Save the document to ``path`` and adopt that file, exactly as ``save`` does.

        Raises ``OSError`` under the same conditions as ``save``.

        Args:
            path: Destination file path.
        """
    def save_copy(self, path: str) -> None:
        """Write the current bytes to ``path`` without adopting it.

        The document keeps its own path, mapping and modified state, so the copy never becomes the file a later
        ``save`` writes to. The copy is written through a temporary file renamed into place and streamed out in chunks
        of the chunk-size hint without holding the document lock across the file write. Raises ``OSError`` when the
        file cannot be written.

        Args:
            path: Destination file path.
        """
    def close(self) -> None:
        """Release the file mapping, keeping the current bytes in memory.

        Releasing the mapping also releases the lock against other writers, so on Windows the file can be written,
        replaced or deleted again. The document stays usable for reads, edits and saves, and its path and modified
        state are unchanged. Closing a document that maps no file does nothing.
        """
    def length(self) -> int:
        """Return the document length.

        Returns:
            int: The number of bytes in the document.
        """
    def read(self, offset: int, length: int) -> bytes:
        """Read up to ``length`` bytes starting at ``offset``.

        The read is clamped to the end of the document, so an ``offset`` equal to the document length returns empty
        bytes. Raises ``ValueError`` when ``offset`` is past the end.

        Args:
            offset: Offset of the first byte to read.
            length: Maximum number of bytes to read.

        Returns:
            bytes: The bytes read.
        """
    def read_byte(self, offset: int) -> int:
        """Read the single byte at ``offset``.

        Raises ``IndexError`` when ``offset`` is at or past the end of the document.

        Args:
            offset: Offset of the byte to read.

        Returns:
            int: The byte value, from 0 to 255.
        """
    def read_window(self, offset: int, length: int) -> tuple[bytes, bytes, int, int]:
        """Read up to ``length`` bytes starting at ``offset`` together with a class tag for each byte.

        Each tag is 0 for a zero byte, 1 for printable ASCII (0x20 to 0x7E), 2 for a control byte (0x01 to 0x1F, or
        0x7F) and 3 for a byte with the high bit set. All four returned values come from one acquisition of the
        document lock, so the generation and length describe the same state the bytes were read from. The read is
        clamped to the end of the document. Raises ``ValueError`` when ``offset`` is past the end.

        Args:
            offset: Offset of the first byte to read.
            length: Maximum number of bytes to read.

        Returns:
            tuple[bytes, bytes, int, int]: The bytes read, one class tag per byte, the document generation at the time
                of the read, and the document length.
        """
    def generation(self) -> int:
        """Return a counter of changes to the document's bytes.

        Every edit, undo and redo that changes bytes advances the counter. Saving, bookmarks, VA mappings, templates
        and the size hints leave it unchanged, so a client can use it as a version number for cached reads.

        Returns:
            int: The current generation.
        """
    def write_bytes(self, offset: int, data: bytes) -> None:
        """Overwrite bytes in place starting at ``offset``.

        The write never grows the document and is recorded as one undoable edit; a write that changes no byte records
        nothing. Raises ``ValueError`` when ``offset`` is at or past the end of the document, or when ``data`` would
        run past the end (``insert_bytes`` grows the document).

        Args:
            offset: Offset of the first byte to overwrite.
            data: Bytes to write.
        """
    def insert_bytes(self, offset: int, data: bytes) -> None:
        """Insert ``data`` at ``offset``, growing the document.

        An ``offset`` equal to the document length appends. The insertion is recorded as one undoable edit. Raises
        ``ValueError`` when ``offset`` is past the end of the document.

        Args:
            offset: Offset the inserted bytes start at.
            data: Bytes to insert.
        """
    def delete_bytes(self, offset: int, length: int) -> None:
        """Delete up to ``length`` bytes starting at ``offset``.

        The range is clamped to the end of the document, and the deletion is recorded as one undoable edit. The GIL is
        released while the edit runs. Raises ``ValueError`` when ``offset`` is at or past the end of the document.

        Args:
            offset: Offset of the first byte to delete.
            length: Maximum number of bytes to delete.
        """
    def undo(self) -> bool:
        """Revert the most recent edit in the undo history.

        Returns:
            bool: True when an edit was reverted, False when there was nothing to undo.
        """
    def redo(self) -> bool:
        """Reapply the most recently undone edit.

        Recording a new edit discards the undone edits, so there is then nothing to redo.

        Returns:
            bool: True when an edit was reapplied, False when there was nothing to redo.
        """
    def can_undo(self) -> bool:
        """Report whether there is an edit to undo.

        Returns:
            bool: True when ``undo`` would revert an edit.
        """
    def can_redo(self) -> bool:
        """Report whether there is an undone edit to redo.

        Returns:
            bool: True when ``redo`` would reapply an edit.
        """
    def is_modified(self) -> bool:
        """Report whether the document has changed since it was opened or last saved.

        The answer comes from the undo history: the document is modified when its current undo position differs from
        the position recorded at the last save, or, for a document never saved, from the empty history. Undoing back to
        the saved position therefore makes the document unmodified again.

        Returns:
            bool: True when the document has unsaved changes.
        """
    def search_bytes(self, pattern: bytes, max_results: int) -> list[tuple[int, int]]:
        """Find occurrences of an exact byte sequence.

        Overlapping occurrences are all reported. An empty pattern matches nothing. The search runs on a snapshot of
        the document with the GIL released.

        Args:
            pattern: Bytes to find.
            max_results: Maximum number of matches to return.

        Returns:
            list[tuple[int, int]]: ``(offset, length)`` for each match, in ascending offset order.
        """
    def search_hex(self, pattern: str, max_results: int) -> list[tuple[int, int]]:
        """Find occurrences of a hex pattern that may contain nibble wildcards.

        The pattern is a sequence of hex digit pairs in which ``?`` stands for any nibble, so ``??`` matches any byte.
        Whitespace and the separators ``_``, ``,``, ``:`` and ``-`` are ignored. Overlapping occurrences are all
        reported. Raises ``ValueError`` for any other character, such as the ``x`` of a ``0x`` prefix, or for an odd
        number of nibbles.

        Args:
            pattern: Hex pattern to find, for example ``"4D 5A ?? 00"``.
            max_results: Maximum number of matches to return.

        Returns:
            list[tuple[int, int]]: ``(offset, length)`` for each match, in ascending offset order.
        """
    def search_text(self, text: str, encoding: str, case_sensitive: bool, max_results: int) -> list[tuple[int, int]]:
        """Find occurrences of ``text`` encoded in ``encoding``.

        Matches may start at any byte offset, including odd offsets for UTF-16, and may overlap. A case-sensitive search
        looks for the exact encoded bytes, so text the encoding cannot represent matches nothing. A case-insensitive
        search compares decoded candidates in lowercase, so a match can differ in byte length from the encoded
        ``text``. Empty ``text`` matches nothing. Raises ``ValueError`` when the encoding name is not recognized.

        Args:
            text: Text to find.
            encoding: Encoding name or label, such as ``utf-8`` or ``utf-16le``; see ``list_encodings``.
            case_sensitive: Whether letter case must match exactly.
            max_results: Maximum number of matches to return.

        Returns:
            list[tuple[int, int]]: ``(offset, length)`` for each match, in ascending offset order.
        """
    def search_regex(self, pattern: str, max_results: int) -> list[tuple[int, int]]:
        """Find matches of a byte-oriented regular expression.

        The expression runs with Unicode mode off, so escapes and classes address raw bytes and ``.`` matches any byte
        except a newline; the inline flag ``(?u)`` turns Unicode mode back on. Matches do not overlap, empty matches are
        skipped, and an empty pattern matches nothing. Raises ``ValueError`` when the pattern does not compile.

        Args:
            pattern: Regular expression to match.
            max_results: Maximum number of matches to return.

        Returns:
            list[tuple[int, int]]: ``(offset, length)`` for each match, in ascending offset order.
        """
    def replace_bytes(self, pattern: bytes, replacement: bytes) -> int:
        """Replace every non-overlapping occurrence of ``pattern`` with ``replacement``.

        Occurrences are found left to right. All replacements together are recorded as one undoable edit, and nothing
        is recorded when no byte changes. Raises ``ValueError`` when ``pattern`` is empty.

        Args:
            pattern: Bytes to replace.
            replacement: Bytes to write in place of each occurrence; may differ in length from ``pattern``.

        Returns:
            int: The number of occurrences replaced.
        """
    def inspect_at(self, offset: int) -> dict[str, str]:
        """Interpret the bytes at ``offset`` as every type the data inspector supports.

        Up to 64 bytes starting at ``offset`` are examined. An interpretation is left out when too few bytes remain or
        the bytes are not a valid value of that type, and an ``offset`` at or past the end yields an empty dict.

        Args:
            offset: Offset of the first byte to interpret.

        Returns:
            dict[str, str]: Interpretation names, such as ``uint32_le``, ``ipv4`` or ``dos_time``, mapped to the
                formatted values.
        """
    def compute_hash(self, algorithm: str) -> str:
        """Compute a digest of the whole document.

        The document is read in chunks of the chunk-size hint, never smaller than 64 KiB, with the GIL released for
        each chunk. Algorithm names are case-insensitive and include ``md5``, ``sha1``, ``sha256``, ``sha512``,
        ``sha3-256``, ``blake2b``, ``xxh3``, ``crc32``, ``adler32`` and ``fnv1a-64``. Raises ``ValueError`` for an
        unsupported algorithm.

        Args:
            algorithm: Name of the hash or checksum algorithm.

        Returns:
            str: The digest as lowercase hex.
        """
    def compute_hash_range(self, start: int, end: int, algorithm: str) -> str:
        """Compute a digest of the bytes from ``start`` up to ``end``.

        ``end`` is exclusive and is clamped to the document length. The range is read in chunks as ``compute_hash``
        reads the whole document. Raises ``ValueError`` when ``start`` is past the clamped end or the algorithm is
        unsupported.

        Args:
            start: Offset of the first byte to hash.
            end: Offset one past the last byte to hash.
            algorithm: Name of the hash or checksum algorithm, as accepted by ``compute_hash``.

        Returns:
            str: The digest as lowercase hex.
        """
    def byte_statistics(self) -> list[tuple[int, int]]:
        """Count how often each byte value occurs in the document.

        The document is read in chunks of the chunk-size hint, never smaller than 64 KiB.

        Returns:
            list[tuple[int, int]]: ``(value, count)`` for all 256 byte values, in ascending value order.
        """
    def add_bookmark(self, offset: int, length: int, label: str, color: str) -> int:
        """Add a bookmark over ``length`` bytes starting at ``offset``.

        Bookmarks are kept in the order they were added and are not part of the undo history.

        Args:
            offset: First byte of the range.
            length: Number of bytes in the range.
            label: User-visible name.
            color: Display color, as the UI's color string.

        Returns:
            int: The index of the new bookmark.
        """
    def add_bookmark_object(self, bookmark: Bookmark) -> int:
        """Add a copy of ``bookmark`` after the existing bookmarks.

        Args:
            bookmark: Bookmark to add.

        Returns:
            int: The index of the new bookmark.
        """
    def remove_bookmark(self, index: int) -> bool:
        """Remove the bookmark at ``index``; later bookmarks move down one index.

        Args:
            index: Index of the bookmark to remove.

        Returns:
            bool: True when a bookmark existed at ``index``.
        """
    def list_bookmarks(self) -> list[tuple[int, int, str, str]]:
        """List every bookmark as a tuple.

        Returns:
            list[tuple[int, int, str, str]]: ``(offset, length, label, color)`` for each bookmark, in index order.
        """
    def get_bookmarks(self) -> list[Bookmark]:
        """Return copies of every bookmark.

        Changing a returned object does not change the document; use ``update_bookmark`` for that.

        Returns:
            list[Bookmark]: Copies of the bookmarks, in index order.
        """
    def get_bookmark(self, index: int) -> Bookmark | None:
        """Return a copy of the bookmark at ``index``.

        Args:
            index: Index of the bookmark.

        Returns:
            Bookmark | None: A copy of the bookmark, or None when ``index`` is out of range.
        """
    def update_bookmark(self, index: int, bookmark: Bookmark) -> bool:
        """Replace the bookmark at ``index`` with a copy of ``bookmark``.

        Args:
            index: Index of the bookmark to replace.
            bookmark: New bookmark values.

        Returns:
            bool: True when a bookmark existed at ``index`` and was replaced.
        """
    def apply_template(self, name: str, offset: int) -> list[dict[str, Any]]:
        """Parse the structure at ``offset`` with the template ``name``.

        Each field is a dict with the keys ``name``, ``offset`` (absolute), ``size``, ``raw_bytes``, ``display_value``,
        ``description``, ``color`` (a string, or None), ``validation_passed`` (a bool, or None when the field has no
        validation) and ``children`` (nested field dicts for array elements, flags and struct members). The template is
        evaluated with the GIL released. Raises ``ValueError`` when no template has that name, when the data is too
        short for the structure, or when evaluation fails.

        Args:
            name: Name of a registered template; see ``list_templates``.
            offset: Offset the structure starts at.

        Returns:
            list[dict[str, Any]]: The parsed top-level fields, in template order.
        """
    def list_templates(self) -> list[tuple[str, str]]:
        """List the registered templates, built-in and user-registered.

        Returns:
            list[tuple[str, str]]: ``(name, description)`` for each template, in name order.
        """
    def detect_templates(self, offset: int) -> list[str]:
        """Find the templates whose declared magic bytes match the data at ``offset``.

        A template without declared magic bytes is never reported. Raises ``ValueError`` when ``offset`` is past the end
        of the document.

        Args:
            offset: Offset the structure would start at.

        Returns:
            list[str]: The names of the matching templates, in name order.
        """
    def register_json_template(self, json_str: str) -> str:
        """Register a template defined in JSON.

        A template already registered under the same name, built-in or not, is replaced. Raises ``ValueError`` when the
        JSON is invalid or does not describe a valid template.

        Args:
            json_str: The template definition as a JSON string.

        Returns:
            str: The template name the JSON declares.
        """
    def remove_template(self, name: str) -> bool:
        """Remove the template registered under ``name``.

        Args:
            name: Name of the template to remove.

        Returns:
            bool: True when a template with that name existed.
        """
    def export_template_json(self, name: str) -> str:
        """Serialize the template ``name`` to JSON.

        Raises ``ValueError`` when no template has that name.

        Args:
            name: Name of the template to export.

        Returns:
            str: The template definition as a JSON string.
        """
    def list_templates_detailed(self) -> list[tuple[str, str, str, int]]:
        """List the registered templates with their category and field count.

        Returns:
            list[tuple[str, str, str, int]]: ``(name, description, category, field_count)`` for each template, in name
                order, with an empty category for a template that declares none.
        """
    def file_path(self) -> str | None:
        """Return the path the document was opened from or last saved to.

        Returns:
            str | None: The file path, or None for a document that has no file.
        """
    def entropy(self) -> float:
        """Compute the Shannon entropy of the whole document.

        The computation runs on a snapshot of the document with the GIL released.

        Returns:
            float: The entropy in bits per byte, from 0.0 to 8.0; 0.0 for an empty document.
        """
    def entropy_map(self, block_size: int) -> list[float]:
        """Compute the Shannon entropy of each consecutive block of the document.

        The last block may be shorter than ``block_size``, and an empty document yields an empty list. Raises
        ``ValueError`` when ``block_size`` is 0.

        Args:
            block_size: Number of bytes in each block.

        Returns:
            list[float]: The entropy of each block in bits per byte, in document order.
        """
    def entropy_map_bytes(self, block_size: int) -> bytes:
        """Compute the same per-block entropies as ``entropy_map``, packed as bytes.

        Raises ``ValueError`` when ``block_size`` is 0.

        Args:
            block_size: Number of bytes in each block.

        Returns:
            bytes: Each block's entropy as a little-endian 64-bit float, eight bytes per block, in document order.
        """
    def byte_distribution_full(self) -> list[int]:
        """Count how often each byte value occurs in the document.

        Returns:
            list[int]: 256 counts, indexed by byte value.
        """
    def byte_distribution_bytes(self) -> bytes:
        """Count how often each byte value occurs, packed as bytes.

        Returns:
            bytes: 2048 bytes holding the 256 counts as little-endian unsigned 64-bit integers, indexed by byte value.
        """
    def byte_type_distribution(self) -> tuple[int, int, int, int]:
        """Count the document's bytes by class.

        Returns:
            tuple[int, int, int, int]: The counts of zero bytes, printable ASCII bytes (0x20 to 0x7E), control bytes
                (0x01 to 0x1F, and 0x7F) and bytes with the high bit set.
        """
    def digram_matrix(self) -> list[int]:
        """Count every pair of adjacent bytes in the document.

        Returns:
            list[int]: 65536 counts in a 256x256 row-major grid, where entry ``a * 256 + b`` counts the positions at
                which byte ``a`` is followed by byte ``b``.
        """
    def digram_matrix_bytes(self) -> bytes:
        """Count every pair of adjacent bytes, packed as bytes.

        Returns:
            bytes: 524288 bytes holding the ``digram_matrix`` counts as little-endian unsigned 64-bit integers, in the
                same order.
        """
    def content_classification(self, block_size: int) -> bytes:
        """Classify each consecutive block of the document by its content.

        The rules are applied in order: 0 (null-heavy) for entropy below 0.5 with more than 90% zero bytes, 1 (text)
        for entropy below 4.5 with more than 70% printable ASCII, 3 (high entropy) for entropy above 7.0 bits per byte,
        4 (mixed) for entropy from 4.5 to 7.0 inclusive, and 2 (structured or other) for anything else. The last block
        may be shorter than ``block_size``. Raises ``ValueError`` when ``block_size`` is 0.

        Args:
            block_size: Number of bytes in each block.

        Returns:
            bytes: One class code per block, in document order.
        """
    def transform_data(self, name: str, offset: int, length: int, params: dict[str, bytes]) -> bytes:
        """Apply a named transform to a range of the document and return the result.

        The document itself is not changed. The range is clamped to the end of the document. Raises ``ValueError``
        when ``offset`` is past the end, the transform name is unknown, a required parameter is missing or invalid, or
        the transform fails.

        Args:
            name: Transform name; see ``list_transforms``.
            offset: Offset of the first byte to transform.
            length: Maximum number of bytes to transform.
            params: Transform parameters as bytes values keyed by parameter name, such as ``key`` for the XOR
                transforms.

        Returns:
            bytes: The transformed bytes.
        """
    @staticmethod
    def list_transforms() -> list[tuple[str, str, str]]:
        """List every transform ``transform_data`` accepts.

        Returns:
            list[tuple[str, str, str]]: ``(name, category, description)`` for each transform, in catalog order.
        """
    def get_patches(self) -> list[tuple[int, bytes]]:
        """Return the byte writes recorded in the undo history, in chronological order.

        Edits that write in place contribute the bytes they wrote; a move contributes zeros at its source as well as
        the moved bytes, and an edit that replaced the whole document contributes its new contents at offset 0.
        Inserts and deletes are skipped, and undone edits are not included.

        Returns:
            list[tuple[int, bytes]]: ``(offset, bytes)`` for each write.
        """
    def export_patches_ips(self) -> bytes:
        """Export the edit history as an IPS patch.

        Overlapping writes are merged so the newest bytes win. Raises ``ValueError`` when the history inserts, deletes
        or resizes bytes (a BPS or UPS patch can express those), when a write reaches past offset 0xFFFFFF, or when
        the patch cannot be encoded.

        Returns:
            bytes: The IPS patch.
        """
    def export_patches_ips32(self) -> bytes:
        """Export the edit history as an IPS32 patch.

        Overlapping writes are merged so the newest bytes win. Raises ``ValueError`` when the history inserts, deletes
        or resizes bytes, when a write reaches past offset 0xFFFFFFFF, or when the patch cannot be encoded.

        Returns:
            bytes: The IPS32 patch.
        """
    def export_patches_cod(self) -> bytes:
        """Export the edit history as a COD patch.

        Each record is a 4-byte big-endian offset, a 4-byte big-endian length and the patched bytes, with no header or
        terminator. Raises ``ValueError`` when the history inserts, deletes or resizes bytes, or when an offset or
        length does not fit in 32 bits.

        Returns:
            bytes: The COD patch.
        """
    def export_patches_json(self) -> str:
        """Export the edit history as a JSON patch.

        Each record is an object with an integer ``offset`` and a lowercase hex ``data`` string. Raises ``ValueError``
        when the history inserts, deletes or resizes bytes.

        Returns:
            str: The patch as pretty-printed JSON.
        """
    def import_patches_ips(self, data: bytes) -> int:
        """Apply an IPS or IPS32 patch to the document as one undoable edit.

        The format is chosen from the ``PATCH`` or ``IPS32`` header. Records that start at or past the end of the
        document are skipped and records that run past the end are cut at it, so the patch never grows the document;
        a truncation length after the terminator shortens the document when it is shorter than the document. Raises
        ``ValueError`` when the patch is malformed.

        Args:
            data: The IPS or IPS32 patch.

        Returns:
            int: The number of records that start inside the document.
        """
    def decode_text(self, offset: int, length: int, encoding: str) -> str:
        """Decode a range of the document as text.

        The range is clamped to the end of the document. The bytes are decoded as ``encoding`` even when they start
        with a byte-order mark for another encoding, and malformed bytes are decoded leniently instead of raising.
        Raises ``ValueError`` when ``offset`` is past the end or the encoding name is not recognized.

        Args:
            offset: Offset of the first byte to decode.
            length: Maximum number of bytes to decode.
            encoding: Encoding name or label; see ``list_encodings``.

        Returns:
            str: The decoded text.
        """
    @staticmethod
    def encode_text_to_bytes(text: str, encoding: str) -> bytes:
        """Encode ``text`` in the named encoding.

        Encoding names are matched case-insensitively, and WHATWG encoding labels are also accepted. Raises
        ``ValueError`` when the encoding name is not recognized or ``text`` contains a character the encoding cannot
        represent.

        Args:
            text: Text to encode.
            encoding: Encoding name or label; see ``list_encodings``.

        Returns:
            bytes: The encoded text.
        """
    @staticmethod
    def list_encodings() -> list[tuple[str, str]]:
        """List the text encodings offered to users.

        Returns:
            list[tuple[str, str]]: ``(name, description)`` for each encoding.
        """
    def search_text_encoded(self, text: str, encoding: str, case_sensitive: bool, max_results: int) -> list[tuple[int, int]]:
        """Find occurrences of ``text`` encoded in ``encoding``, using the engine behind ``search_text``.

        This returns the same matches as ``search_text``: overlapping matches at any byte offset, exact encoded bytes
        when ``case_sensitive`` is true, and lowercase comparison of decoded candidates otherwise. Raises
        ``ValueError`` when the encoding name is not recognized.

        Args:
            text: Text to find.
            encoding: Encoding name or label; see ``list_encodings``.
            case_sensitive: Whether letter case must match exactly.
            max_results: Maximum number of matches to return.

        Returns:
            list[tuple[int, int]]: ``(offset, length)`` for each match, in ascending offset order.
        """
    def search_numeric(
        self,
        value: int,
        size: int,
        signed: bool,
        big_endian: bool,
        alignment: int,
        max_results: int,
    ) -> list[tuple[int, int]]:
        """Find integers equal to ``value`` stored in ``size`` bytes.

        Only offsets that are multiples of ``alignment`` are examined, and an alignment of 0 is treated as 1. A value
        that does not fit the width and signedness matches nothing. Raises ``ValueError`` when ``size`` is not between
        1 and 8.

        Args:
            value: Integer to find.
            size: Width of the stored integer in bytes, from 1 to 8.
            signed: Whether the integer is stored as two's complement.
            big_endian: Whether the integer is stored big-endian rather than little-endian.
            alignment: Step between examined offsets.
            max_results: Maximum number of matches to return.

        Returns:
            list[tuple[int, int]]: ``(offset, length)`` for each match, in ascending offset order.
        """
    def search_numeric_float(
        self,
        value: float,
        size: int,
        big_endian: bool,
        tolerance: float,
        alignment: int,
        max_results: int,
    ) -> list[tuple[int, int]]:
        """Find IEEE 754 floats within ``tolerance`` of ``value``.

        Only offsets that are multiples of ``alignment`` are examined, and an alignment of 0 is treated as 1. Stored
        NaN and infinity values never match. Raises ``ValueError`` when ``size`` is not 4 or 8, when ``value`` is not
        finite, or when ``tolerance`` is negative or not finite.

        Args:
            value: Number to find.
            size: Width of the stored float in bytes, 4 or 8.
            big_endian: Whether the float is stored big-endian rather than little-endian.
            tolerance: Largest accepted absolute difference from ``value``, inclusive.
            alignment: Step between examined offsets.
            max_results: Maximum number of matches to return.

        Returns:
            list[tuple[int, int]]: ``(offset, length)`` for each match, in ascending offset order.
        """
    def search_numeric_range(
        self,
        value_range: tuple[int, int],
        size: int,
        signed: bool,
        big_endian: bool,
        alignment: int,
        max_results: int,
    ) -> list[tuple[int, int]]:
        """Find integers stored in ``size`` bytes whose value lies in an inclusive range.

        Only offsets that are multiples of ``alignment`` are examined, and an alignment of 0 is treated as 1. A range
        whose minimum exceeds its maximum matches nothing. For an unsigned search a negative minimum is treated as 0,
        so a range lying entirely below zero matches nothing. Raises ``ValueError`` when ``size`` is not between 1 and
        8.

        Args:
            value_range: ``(minimum, maximum)``, both inclusive.
            size: Width of the stored integer in bytes, from 1 to 8.
            signed: Whether the integer is stored as two's complement.
            big_endian: Whether the integer is stored big-endian rather than little-endian.
            alignment: Step between examined offsets.
            max_results: Maximum number of matches to return.

        Returns:
            list[tuple[int, int]]: ``(offset, length)`` for each match, in ascending offset order.
        """
    def compute_hash_custom_crc(
        self,
        byte_range: tuple[int, int],
        poly: int,
        init: int,
        width: int,
        reflect: tuple[bool, bool],
        xorout: int,
    ) -> str:
        """Compute a CRC with custom parameters over a range of the document.

        The range end is exclusive and is clamped to the document length. The polynomial, initial value and final XOR
        are masked to ``width`` bits. Raises ``ValueError`` when the range start is past the clamped end or ``width``
        is not 8, 16, 32 or 64.

        Args:
            byte_range: ``(start, end)`` offsets of the bytes to checksum.
            poly: Generator polynomial in normal (non-reflected) form, without its top bit.
            init: Initial register value.
            width: CRC width in bits: 8, 16, 32 or 64.
            reflect: ``(reflect_in, reflect_out)``: whether each input byte is bit-reflected and whether the final
                register is bit-reflected before the final XOR.
            xorout: Value XORed into the final register.

        Returns:
            str: The CRC as lowercase hex, zero-padded to ``width / 4`` digits.
        """
    @staticmethod
    def from_process_memory(pid: int, address: int, size: int) -> HexDocument:
        """Create a document from a copy of another process's memory (Windows only).

        The process is opened for reading only, and ``size`` bytes starting at ``address`` are copied into a new
        in-memory document with no file path; the document does not stay attached to the process. The read runs with
        the GIL released. Raises ``RuntimeError`` when the process cannot be opened, when the read fails or copies
        fewer bytes than requested, and on platforms other than Windows.

        Args:
            pid: Process ID of the target process.
            address: Virtual address of the first byte to copy.
            size: Number of bytes to copy.

        Returns:
            HexDocument: The new document holding the copied bytes.
        """
    @staticmethod
    def list_process_memory_regions(pid: int) -> list[tuple[int, int, int, int]]:
        """List the memory regions of another process (Windows only).

        Every region ``VirtualQueryEx`` reports while walking the address space from address 0 is included, whatever
        its state. Raises ``RuntimeError`` when the process cannot be opened or a query fails, and on platforms other
        than Windows.

        Args:
            pid: Process ID of the target process.

        Returns:
            list[tuple[int, int, int, int]]: ``(base_address, size, protection, state)`` for each region, where
                ``protection`` holds the ``PAGE_*`` flags and ``state`` is ``MEM_COMMIT``, ``MEM_RESERVE`` or
                ``MEM_FREE``.
        """
    def export_patches_bps(self, source_data: bytes) -> bytes:
        """Create a BPS patch that turns ``source_data`` into the current document.

        The patch is encoded with the GIL released. Raises ``ValueError`` when the encoder reports an error.

        Args:
            source_data: The original bytes the patch applies to.

        Returns:
            bytes: The BPS patch.
        """
    def export_patches_bps_from_path(self, source_path: str) -> bytes:
        """Create a BPS patch that turns the file at ``source_path`` into the current document.

        The source file is loaded by the extension instead of passing through Python: on Windows it is mapped
        read-only and locked against writers, and it is copied into memory when it is empty, when another handle can
        write it, and on other platforms. Raises ``OSError`` when the path is not a regular file or cannot be opened,
        mapped or read, and ``ValueError`` when the encoder reports an error.

        Args:
            source_path: Path of the original file the patch applies to.

        Returns:
            bytes: The BPS patch.
        """
    def import_patches_bps(self, patch_data: bytes, source_data: bytes) -> int:
        """Replace the document with the target a BPS patch produces from ``source_data``.

        The ``BPS1`` header, the declared source size and the source, target and patch CRC32 checksums are validated.
        The replacement is recorded as one undoable edit, and the document keeps its file path. Raises ``ValueError``
        when the patch is malformed, a checksum does not match, or ``source_data`` is not the source the patch
        expects.

        Args:
            patch_data: The BPS patch.
            source_data: The original bytes the patch applies to.

        Returns:
            int: The length of the new document contents.
        """
    def export_patches_ups(self, source_data: bytes) -> bytes:
        """Create a UPS patch that turns ``source_data`` into the current document.

        The patch is encoded with the GIL released. Raises ``ValueError`` when the encoder reports an error.

        Args:
            source_data: The original bytes the patch applies to.

        Returns:
            bytes: The UPS patch.
        """
    def export_patches_ups_from_path(self, source_path: str) -> bytes:
        """Create a UPS patch that turns the file at ``source_path`` into the current document.

        The source file is loaded as ``export_patches_bps_from_path`` loads it. Raises ``OSError`` when the path is not
        a regular file or cannot be opened, mapped or read, and ``ValueError`` when the encoder reports an error.

        Args:
            source_path: Path of the original file the patch applies to.

        Returns:
            bytes: The UPS patch.
        """
    def import_patches_ups(self, patch_data: bytes, source_data: bytes) -> int:
        """Replace the document with the target a UPS patch produces from ``source_data``.

        The ``UPS1`` header, the declared source size and the source, target and patch CRC32 checksums are validated.
        The replacement is recorded as one undoable edit, and the document keeps its file path. Raises ``ValueError``
        when the patch is malformed, a checksum does not match, or ``source_data`` is not the source the patch
        expects.

        Args:
            patch_data: The UPS patch.
            source_data: The original bytes the patch applies to.

        Returns:
            int: The length of the new document contents.
        """
    def fill_block(self, offset: int, length: int, pattern: bytes) -> None:
        """Overwrite ``length`` bytes starting at ``offset`` with ``pattern`` repeated.

        The pattern is repeated and cut to exactly ``length`` bytes. The fill is recorded as one undoable edit and runs
        with the GIL released. Raises ``ValueError`` when ``pattern`` is empty or the block extends past the end of the
        document.

        Args:
            offset: Offset of the first byte to fill.
            length: Number of bytes to fill.
            pattern: Bytes to repeat across the block.
        """
    def copy_block(self, src_offset: int, length: int, dst_offset: int) -> None:
        """Copy ``length`` bytes from ``src_offset`` over the bytes at ``dst_offset``.

        The source is read before the destination is written, so the blocks may overlap, and the document length does
        not change. The copy is recorded as one undoable edit and runs with the GIL released. Raises ``ValueError``
        when either block extends past the end of the document.

        Args:
            src_offset: Offset of the first byte to copy.
            length: Number of bytes to copy.
            dst_offset: Offset the copied bytes are written to.
        """
    def move_block(self, src_offset: int, length: int, dst_offset: int) -> None:
        """Move ``length`` bytes from ``src_offset`` to ``dst_offset``, filling the source with zeros.

        The destination bytes are overwritten and the document length does not change. The move is recorded as one
        undoable edit and runs with the GIL released. Raises ``ValueError`` when either block extends past the end of
        the document or the blocks overlap.

        Args:
            src_offset: Offset of the first byte to move.
            length: Number of bytes to move.
            dst_offset: Offset the moved bytes are written to.
        """
    def swap_blocks(self, offset_a: int, len_a: int, offset_b: int, len_b: int) -> None:
        """Exchange the contents of two equal-length, non-overlapping blocks.

        The swap is recorded as one undoable edit and runs with the GIL released. Raises ``ValueError`` when the
        lengths differ, when either block extends past the end of the document, or when the blocks overlap.

        Args:
            offset_a: Offset of the first block.
            len_a: Length of the first block.
            offset_b: Offset of the second block.
            len_b: Length of the second block; must equal ``len_a``.
        """
    def get_bit(self, offset: int, bit_index: int) -> bool:
        """Read one bit of the byte at ``offset``.

        Raises ``ValueError`` when ``bit_index`` is greater than 7, and ``IndexError`` when ``offset`` is at or past
        the end of the document.

        Args:
            offset: Offset of the byte.
            bit_index: Bit position, where 0 is the least significant bit.

        Returns:
            bool: True when the bit is set.
        """
    def set_bit(self, offset: int, bit_index: int, value: bool) -> None:
        """Set one bit of the byte at ``offset`` to ``value``.

        The change is recorded as one undoable edit when it changes the byte. Raises ``ValueError`` when ``bit_index``
        is greater than 7, and ``IndexError`` when ``offset`` is at or past the end of the document.

        Args:
            offset: Offset of the byte.
            bit_index: Bit position, where 0 is the least significant bit.
            value: True to set the bit, False to clear it.
        """
    def toggle_bit(self, offset: int, bit_index: int) -> bool:
        """Flip one bit of the byte at ``offset``.

        The change is recorded as one undoable edit. Raises ``ValueError`` when ``bit_index`` is greater than 7, and
        ``IndexError`` when ``offset`` is at or past the end of the document.

        Args:
            offset: Offset of the byte.
            bit_index: Bit position, where 0 is the least significant bit.

        Returns:
            bool: The new value of the bit.
        """
    def add_va_mapping(self, file_offset: int, virtual_address: int, length: int) -> None:
        """Map ``length`` bytes starting at ``file_offset`` linearly onto addresses starting at ``virtual_address``.

        Mappings are kept sorted by file offset, so the indices ``remove_va_mapping`` takes follow that order. Mappings
        are not checked against the document length, are not shifted by later inserts or deletes, and are not part of
        the undo history.

        Args:
            file_offset: File offset of the first mapped byte.
            virtual_address: Virtual address of the first mapped byte.
            length: Number of bytes the mapping covers.
        """
    def remove_va_mapping(self, index: int) -> bool:
        """Remove the VA mapping at ``index`` in file-offset order.

        Args:
            index: Index of the mapping to remove.

        Returns:
            bool: True when a mapping existed at ``index``.
        """
    def list_va_mappings(self) -> list[tuple[int, int, int]]:
        """List every VA mapping.

        Returns:
            list[tuple[int, int, int]]: ``(file_offset, virtual_address, length)`` for each mapping, sorted by file
                offset.
        """
    def file_offset_to_va(self, offset: int) -> int | None:
        """Translate a file offset to a virtual address through the registered mappings.

        The first mapping in file-offset order that contains ``offset`` decides the answer. The offset is not checked
        against the document length.

        Args:
            offset: File offset to translate.

        Returns:
            int | None: The virtual address, or None when no mapping contains ``offset`` or the address would exceed
                the unsigned 64-bit range.
        """
    def va_to_file_offset(self, va: int) -> int | None:
        """Translate a virtual address to a file offset through the registered mappings.

        The first mapping in file-offset order whose address range contains ``va`` decides the answer. The result can
        lie at or past the end of the document, for example for a section whose virtual size exceeds its raw size,
        so check it against the document length before reading.

        Args:
            va: Virtual address to translate.

        Returns:
            int | None: The file offset, or None when no mapping contains ``va`` or the offset would overflow.
        """
    def extract_strings(
        self,
        min_length: int,
        include_ascii: bool,
        include_utf16: bool,
        max_results: int,
        include_utf16be: bool = False,
    ) -> list[dict[str, Any]]:
        """Extract printable strings from the document.

        UTF-16 strings are found at both even and odd offsets. The UTF-16LE and UTF-16BE scans are independent, so
        enabling both can report the same bytes once under each reading. Each result is a dict with the keys
        ``offset``, ``length`` (in bytes), ``encoding`` (``ascii``, ``utf16le`` or ``utf16be``) and ``content``. The
        scan runs on a snapshot of the document with the GIL released.

        Args:
            min_length: Minimum string length in characters.
            include_ascii: Whether to report printable ASCII strings.
            include_utf16: Whether to report UTF-16LE strings.
            max_results: Maximum number of strings to return.
            include_utf16be: Whether to report UTF-16BE strings.

        Returns:
            list[dict[str, Any]]: The strings sorted by offset; at equal offsets ASCII comes before UTF-16LE, and
                UTF-16LE before UTF-16BE.
        """
    def verify_pe_checksum(self) -> dict[str, Any]:
        """Compare the PE image checksum stored in the optional header with the computed one.

        The checksum is computed with the Windows algorithm over the whole document, skipping the ``CheckSum`` field.
        Raises ``ValueError`` when the document is not a PE image (shorter than 64 bytes, or without the ``MZ`` or
        ``PE`` signature), when the ``CheckSum`` field lies past the end, or when the PE header starts at an odd
        offset.

        Returns:
            dict[str, Any]: ``stored`` and ``calculated`` checksums as integers, ``offset``, the file offset of the
                ``CheckSum`` field, and ``valid``, True when the two checksums match.
        """
    def repair_pe_checksum(self) -> None:
        """Write the computed PE image checksum into the ``CheckSum`` field.

        The write is recorded as one undoable edit, and nothing is recorded when the stored checksum is already
        correct. Raises ``ValueError`` under the same conditions as ``verify_pe_checksum``.
        """
    def get_document_memory_usage(self) -> int:
        """Return the document length as its memory-usage figure.

        The figure is a lower bound on the memory the document holds; the undo history and piece-table bookkeeping are
        not counted.

        Returns:
            int: The document length in bytes.
        """
    def set_chunk_size_hint(self, size: int) -> None:
        """Set the read size that chunked operations use.

        ``compute_hash``, ``compute_hash_range``, ``byte_statistics`` and ``save_copy`` read the document in chunks of
        this size, but never smaller than 64 KiB. The hint is stored without taking the document lock.

        Args:
            size: Chunk size in bytes.
        """
    def get_chunk_size_hint(self) -> int:
        """Return the chunk-size hint as last set.

        The value is returned as stored, before the 64 KiB minimum is applied. A new document starts at 4 MiB. The hint
        is read without taking the document lock.

        Returns:
            int: The chunk-size hint in bytes.
        """
    def set_memory_budget_hint(self, budget: int) -> None:
        """Set the memory-budget hint.

        The document stores the value for clients to read back with ``get_memory_budget_hint`` and does not use it
        itself. The hint is stored without taking the document lock.

        Args:
            budget: Memory budget in bytes.
        """
    def get_memory_budget_hint(self) -> int:
        """Return the memory-budget hint as last set.

        A new document starts at 512 MiB. The hint is read without taking the document lock.

        Returns:
            int: The memory-budget hint in bytes.
        """

def diff_files(path_a: str, path_b: str, min_match: int = 1, max_regions: int = 100_000) -> dict[str, Any]: ...
def diff_bytes(data_a: bytes, data_b: bytes, min_match: int = 1, max_regions: int = 100_000) -> dict[str, Any]: ...
