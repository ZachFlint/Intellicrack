from typing import Any

import torch

class PreTrainedTokenizerBase:
    pad_token_id: int | None
    eos_token_id: int | None
    pad_token: str | None
    eos_token: str | None
    chat_template: str | None
    def __call__(
        self,
        text: str | list[str],
        return_tensors: str | None = ...,
        truncation: bool = ...,
        padding: bool | str = ...,
        max_length: int | None = ...,
        **kwargs: object,
    ) -> BatchEncoding: ...
    def decode(
        self,
        token_ids: torch.Tensor | list[int],
        skip_special_tokens: bool = ...,
        **kwargs: object,
    ) -> str: ...
    def apply_chat_template(
        self,
        conversation: list[dict[str, str]],
        tokenize: bool = ...,
        add_generation_prompt: bool = ...,
        **kwargs: object,
    ) -> str | list[int]: ...

class BatchEncoding:
    def __getitem__(self, key: str) -> torch.Tensor: ...
    def get(self, key: str, default: torch.Tensor | None = ...) -> torch.Tensor | None: ...

class PretrainedConfig:
    def __init__(self, **kwargs: object) -> None: ...

class LlamaConfig(PretrainedConfig):
    def __init__(
        self,
        *,
        vocab_size: int = ...,
        hidden_size: int = ...,
        intermediate_size: int = ...,
        num_hidden_layers: int = ...,
        num_attention_heads: int = ...,
        num_key_value_heads: int | None = ...,
        max_position_embeddings: int = ...,
        tie_word_embeddings: bool = ...,
        **kwargs: object,
    ) -> None: ...

class PreTrainedModel:
    def generate(
        self,
        inputs: torch.Tensor | None = ...,
        attention_mask: torch.Tensor | None = ...,
        max_new_tokens: int | None = ...,
        temperature: float | None = ...,
        do_sample: bool = ...,
        pad_token_id: int | None = ...,
        eos_token_id: int | None = ...,
        **kwargs: object,
    ) -> torch.Tensor: ...
    def __call__(
        self,
        input_ids: torch.Tensor | None = ...,
        attention_mask: torch.Tensor | None = ...,
        past_key_values: tuple[tuple[torch.Tensor, ...], ...] | None = ...,
        use_cache: bool = ...,
        **kwargs: object,
    ) -> Any: ...
    def eval(self) -> PreTrainedModel: ...
    def to(self, device: torch.device | str, **kwargs: object) -> PreTrainedModel: ...
    def state_dict(self) -> dict[str, torch.Tensor]: ...
    def save_pretrained(
        self,
        save_directory: str,
        *,
        max_shard_size: int | str = ...,
        safe_serialization: bool = ...,
        **kwargs: object,
    ) -> None: ...

class LlamaForCausalLM(PreTrainedModel):
    def __init__(self, config: LlamaConfig) -> None: ...

class AutoModelForCausalLM:
    @staticmethod
    def from_pretrained(
        pretrained_model_name_or_path: str,
        **kwargs: object,
    ) -> PreTrainedModel: ...

class AutoTokenizer:
    @staticmethod
    def from_pretrained(
        pretrained_model_name_or_path: str,
        **kwargs: object,
    ) -> PreTrainedTokenizerBase: ...

class BitsAndBytesConfig:
    def __init__(
        self,
        load_in_8bit: bool = ...,
        load_in_4bit: bool = ...,
        bnb_4bit_compute_dtype: torch.dtype | None = ...,
        bnb_4bit_use_double_quant: bool = ...,
        **kwargs: object,
    ) -> None: ...
