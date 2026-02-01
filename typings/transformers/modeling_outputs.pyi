import torch

class CausalLMOutputWithPast:
    logits: torch.Tensor
    past_key_values: tuple[tuple[torch.Tensor, ...], ...] | None
