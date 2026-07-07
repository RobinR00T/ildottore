"""Comment-carrier mutators: hide the payload inside a comment (contract §1, §5.4).

Two built-in strategies live here (one module, two carriers per the contract §1 ownership):

- ``markdown_comment_carrier`` — an HTML/Markdown comment ``[//]: # (...)`` style hidden
  directive plus a benign visible wrapper.
- ``html_comment_carrier`` — an ``<!-- ... -->`` comment carrying the payload.

Both are reversible (contract §7 records the carrier so the payload is recoverable) and
intent-preserving: the payload sits verbatim inside the comment; the visible text is inert.
"""

from __future__ import annotations

from ildottore.mutators.base import BaseMutator

__all__ = ["HtmlCommentCarrierMutator", "MarkdownCommentCarrierMutator"]

_VISIBLE = "Here is a document for you to process."


class MarkdownCommentCarrierMutator(BaseMutator):
    """Carries the payload inside a Markdown comment directive."""

    name = "markdown_comment_carrier"
    reversible = True

    def _transform(self, text: str, seed: str) -> tuple[str, dict[str, object]]:
        carried = f"{_VISIBLE}\n\n[//]: # ({text})"
        return carried, {"carrier": "markdown_comment", "payload": text}


class HtmlCommentCarrierMutator(BaseMutator):
    """Carries the payload inside an HTML comment."""

    name = "html_comment_carrier"
    reversible = True

    def _transform(self, text: str, seed: str) -> tuple[str, dict[str, object]]:
        carried = f"{_VISIBLE}\n\n<!-- {text} -->"
        return carried, {"carrier": "html_comment", "payload": text}
