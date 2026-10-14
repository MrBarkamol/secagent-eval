"""The LLM security agent: loop + tools + verifier, behind a model seam."""

from .adapter import ModelAdapter, MockModel, OllamaAdapter
from .loop import AgentDetector
from .tools import ToolContext

__all__ = ["ModelAdapter", "MockModel", "OllamaAdapter", "AgentDetector", "ToolContext"]
