"""AI provider abstraction."""

from .explain import ExplanationResult, explain
from .provider import AIProvider, MockProvider, OpenAICompatibleProvider, get_provider
from .schema import AIExplanation, AIValidationError

__all__ = [
    "AIExplanation",
    "AIProvider",
    "AIValidationError",
    "ExplanationResult",
    "MockProvider",
    "OpenAICompatibleProvider",
    "explain",
    "get_provider",
]
