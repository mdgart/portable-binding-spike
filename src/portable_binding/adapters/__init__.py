"""Platform envelope adapters."""

from .faramesh import FarameshAdapter
from .github_safe_outputs import GitHubSafeOutputsAdapter

__all__ = ["FarameshAdapter", "GitHubSafeOutputsAdapter"]

