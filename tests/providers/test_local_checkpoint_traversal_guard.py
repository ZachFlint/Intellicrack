# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Falsifiable gates for the local sharded-checkpoint traversal guard.

A sharded HuggingFace checkpoint records its shard file names in a
``*.index.json`` ``weight_map``. ``transformers`` resolves those names for a
local model folder by joining each one directly onto the checkpoint directory,
so a hostile checkpoint can map a weight to ``../`` paths, an absolute/UNC path,
or a Windows reserved device and make the loader read arbitrary files or block
on a device handle (the reachable form of CVE-2026-69112). Intellicrack loads
local models through :func:`load_model_for_cpu` / :func:`load_model_for_xpu` and
``LocalTransformersProvider._load_model_for_cuda`, each of which now calls
:func:`validate_local_checkpoint` before handing the path to ``from_pretrained``.

These gates build **real** sharded safetensors checkpoints with ``torch`` /
``transformers`` and hand-crafted index files, then assert:

* an unguarded ``transformers`` load genuinely reads weights from outside the
  checkpoint folder (so the exploit - and therefore the gate - is real); and
* :func:`validate_local_checkpoint` and the real loader reject every escaping or
  reserved-device shard entry while permitting legitimate in-folder shards.

Removing the guard, or narrowing any single rejection mechanism (absolute /
drive-relative / UNC, ``..`` traversal, or reserved device), reddens a gate.
"""

from __future__ import annotations

import json
import shutil
from typing import TYPE_CHECKING, Final, cast

import pytest
import torch
from transformers import AutoModelForCausalLM, LlamaConfig, LlamaForCausalLM

from intellicrack.core.types import UnsafeCheckpointError
from intellicrack.providers.model_loader import ModelConfig, load_model_for_cpu, validate_local_checkpoint


if TYPE_CHECKING:
    from pathlib import Path


_MIN_SHARD_COUNT: Final[int] = 2
_SHARD_INDEX_NAME: Final[str] = "model.safetensors.index.json"
_TINY_SHARD_SIZE: Final[str] = "10KB"


def _build_sharded_checkpoint(destination: Path) -> list[str]:
    """Write a real, multi-shard safetensors checkpoint to ``destination``.

    Args:
        destination: Directory to save the checkpoint into.

    Returns:
        list[str]: The sorted shard file names recorded in the checkpoint's
            ``weight_map``.
    """
    config = LlamaConfig(
        vocab_size=32,
        hidden_size=16,
        intermediate_size=32,
        num_hidden_layers=2,
        num_attention_heads=2,
        num_key_value_heads=2,
        max_position_embeddings=64,
    )
    model = LlamaForCausalLM(config)
    model.save_pretrained(str(destination), max_shard_size=_TINY_SHARD_SIZE)
    index = json.loads((destination / _SHARD_INDEX_NAME).read_text(encoding="utf-8"))
    weight_map: dict[str, str] = index["weight_map"]
    return sorted(set(weight_map.values()))


def _read_weight_map(checkpoint_dir: Path) -> dict[str, str]:
    """Read and return the ``weight_map`` of a checkpoint's shard index.

    Args:
        checkpoint_dir: Directory holding the ``*.index.json`` file.

    Returns:
        dict[str, str]: The checkpoint's shard ``weight_map``.
    """
    parsed: dict[str, object] = json.loads((checkpoint_dir / _SHARD_INDEX_NAME).read_text(encoding="utf-8"))
    return cast("dict[str, str]", parsed["weight_map"])


def _write_index(checkpoint_dir: Path, weight_map: dict[str, object]) -> None:
    """Write a shard index carrying ``weight_map`` into ``checkpoint_dir``.

    Args:
        checkpoint_dir: Directory to write the index into.
        weight_map: The ``weight_map`` mapping to serialise.
    """
    document = {"metadata": {"total_size": 0}, "weight_map": weight_map}
    (checkpoint_dir / _SHARD_INDEX_NAME).write_text(json.dumps(document), encoding="utf-8")


class TestTraversalCheckpointIsRejectedButReallyExploitable:
    """The guard blocks a traversal checkpoint that transformers would otherwise load."""

    @staticmethod
    def test_unguarded_transformers_reads_weights_outside_the_folder(tmp_path: Path) -> None:
        """Without the guard, a ``../`` shard entry loads weights from another folder.

        This pins the gate to a genuine, reachable exploit: if the join in
        ``transformers`` were not attacker-reachable, the reloaded weights would
        not match the out-of-folder originals and this assertion would fail.
        """
        legit = tmp_path / "legit"
        victim = tmp_path / "victim"
        _build_sharded_checkpoint(legit)
        reference = LlamaForCausalLM.__module__  # touch to keep import meaningful
        assert reference

        original = AutoModelForCausalLM.from_pretrained(str(legit), dtype=torch.float32)
        victim.mkdir()
        for source in legit.iterdir():
            if source.is_file() and source.suffix != ".safetensors":
                shutil.copy2(source, victim / source.name)
        weight_map = _read_weight_map(legit)
        _write_index(victim, {key: f"../legit/{value}" for key, value in weight_map.items()})

        leaked = AutoModelForCausalLM.from_pretrained(str(victim), dtype=torch.float32)
        original_state = original.state_dict()
        leaked_state = leaked.state_dict()
        assert leaked_state.keys() == original_state.keys()
        assert all(torch.equal(leaked_state[key], original_state[key]) for key in original_state)

    @staticmethod
    def test_load_model_for_cpu_rejects_the_traversal_checkpoint(tmp_path: Path) -> None:
        """The real CPU loader raises ``UnsafeCheckpointError`` before ``from_pretrained``.

        Reverting the ``validate_local_checkpoint`` call in ``load_model_for_cpu``
        lets execution reach the tokenizer load instead, which raises a plain
        ``RuntimeError`` (no tokenizer files) rather than ``UnsafeCheckpointError``.
        """
        legit = tmp_path / "legit"
        victim = tmp_path / "victim"
        _build_sharded_checkpoint(legit)
        victim.mkdir()
        shutil.copy2(legit / "config.json", victim / "config.json")
        weight_map = _read_weight_map(legit)
        _write_index(victim, {key: f"../legit/{value}" for key, value in weight_map.items()})

        with pytest.raises(UnsafeCheckpointError) as excinfo:
            load_model_for_cpu(ModelConfig(model_id=str(victim)))
        assert excinfo.value.offending_entry is not None
        assert ".." in excinfo.value.offending_entry


class TestLegitimateCheckpointIsPermitted:
    """A real, well-formed sharded checkpoint passes the guard unchanged."""

    @staticmethod
    def test_validate_allows_a_real_multishard_checkpoint(tmp_path: Path) -> None:
        """The guard does not raise on a genuine multi-shard safetensors checkpoint.

        A guard that rejected in-folder shard names (for example by comparing
        against the wrong base directory) would raise here on a legitimate load.
        """
        legit = tmp_path / "legit"
        shards = _build_sharded_checkpoint(legit)
        assert len(shards) >= _MIN_SHARD_COUNT

        validate_local_checkpoint(str(legit))

        reloaded = AutoModelForCausalLM.from_pretrained(str(legit), dtype=torch.float32)
        assert reloaded.state_dict()


class TestValidateLocalCheckpointMechanisms:
    """Each rejection mechanism of ``validate_local_checkpoint`` is gated on its own."""

    @staticmethod
    def _prepare(checkpoint_dir: Path, entry: object) -> None:
        """Create a checkpoint dir with a single-weight index mapping to ``entry``.

        Args:
            checkpoint_dir: Directory to create and populate.
            entry: The single ``weight_map`` value to record.
        """
        checkpoint_dir.mkdir()
        _write_index(checkpoint_dir, {"model.weight": entry})

    def test_absolute_path_entry_is_rejected(self, tmp_path: Path) -> None:
        """An absolute shard path escapes the folder and must be refused."""
        checkpoint = tmp_path / "cp"
        outside = tmp_path / "outside.safetensors"
        self._prepare(checkpoint, str(outside))
        with pytest.raises(UnsafeCheckpointError):
            validate_local_checkpoint(str(checkpoint))

    def test_drive_relative_entry_is_rejected(self, tmp_path: Path) -> None:
        """A Windows drive-relative shard path (``C:evil``) must be refused."""
        checkpoint = tmp_path / "cp"
        self._prepare(checkpoint, "C:evil.safetensors")
        with pytest.raises(UnsafeCheckpointError):
            validate_local_checkpoint(str(checkpoint))

    def test_unc_path_entry_is_rejected(self, tmp_path: Path) -> None:
        """A UNC shard path (``//host/share/x``) must be refused."""
        checkpoint = tmp_path / "cp"
        self._prepare(checkpoint, "//host/share/evil.safetensors")
        with pytest.raises(UnsafeCheckpointError):
            validate_local_checkpoint(str(checkpoint))

    def test_parent_traversal_entry_is_rejected(self, tmp_path: Path) -> None:
        """A ``..`` shard path that leaves the folder must be refused."""
        checkpoint = tmp_path / "cp"
        self._prepare(checkpoint, "../../secret.safetensors")
        with pytest.raises(UnsafeCheckpointError) as excinfo:
            validate_local_checkpoint(str(checkpoint))
        assert excinfo.value.offending_entry == "../../secret.safetensors"

    def test_reserved_device_entry_is_rejected(self, tmp_path: Path) -> None:
        """A shard path naming a Windows reserved device (``NUL``) must be refused.

        ``NUL`` carries no drive and stays inside the folder string-wise, so only
        the reserved-device mechanism rejects it. Dropping that check would let it
        through.
        """
        checkpoint = tmp_path / "cp"
        self._prepare(checkpoint, "NUL")
        with pytest.raises(UnsafeCheckpointError):
            validate_local_checkpoint(str(checkpoint))

    def test_non_string_entry_is_rejected(self, tmp_path: Path) -> None:
        """A non-string shard entry is not a usable file name and must be refused."""
        checkpoint = tmp_path / "cp"
        self._prepare(checkpoint, 1234)
        with pytest.raises(UnsafeCheckpointError):
            validate_local_checkpoint(str(checkpoint))

    def test_unparseable_index_is_rejected(self, tmp_path: Path) -> None:
        """A shard index that is not valid JSON must be refused, not silently loaded."""
        checkpoint = tmp_path / "cp"
        checkpoint.mkdir()
        (checkpoint / _SHARD_INDEX_NAME).write_text("{not valid json", encoding="utf-8")
        with pytest.raises(UnsafeCheckpointError):
            validate_local_checkpoint(str(checkpoint))

    def test_nested_in_folder_entry_is_allowed(self, tmp_path: Path) -> None:
        """A nested shard path that resolves back inside the folder is permitted."""
        checkpoint = tmp_path / "cp"
        checkpoint.mkdir()
        (checkpoint / "shards").mkdir()
        (checkpoint / "shards" / "w.safetensors").write_bytes(b"\x00")
        _write_index(checkpoint, {"model.weight": "sub/../shards/w.safetensors"})
        validate_local_checkpoint(str(checkpoint))

    def test_directory_without_index_is_allowed(self, tmp_path: Path) -> None:
        """A single-file checkpoint with no shard index has nothing to validate."""
        checkpoint = tmp_path / "cp"
        checkpoint.mkdir()
        (checkpoint / "model.safetensors").write_bytes(b"\x00")
        validate_local_checkpoint(str(checkpoint))

    def test_hub_repo_id_is_a_noop(self, tmp_path: Path) -> None:
        """A non-directory model id (a Hub repo id) is left for the SDK to resolve."""
        missing = tmp_path / "does-not-exist"
        validate_local_checkpoint("meta-llama/Llama-3.2-1B")
        validate_local_checkpoint(str(missing))
