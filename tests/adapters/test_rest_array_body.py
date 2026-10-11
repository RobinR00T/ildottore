"""A REST template whose ``text_path`` starts at an index reads a JSON array body.

Pre-merge audit of 598f0858, LOW 2: Hugging Face's Inference API answers
``[{"generated_text": ...}]``, and every success body that is not a JSON object was refused, so a
template written ``0.generated_text`` could never read one; since OD-21 each such reply was an
unreadable attempt.
"""

from __future__ import annotations

import json

import pytest

from ildottore.adapters import ResponseMalformed, RestAdapter, RestTemplate
from ildottore.shared.models import ModelRequest
from tests.adapters.test_malformed_replies import _ALLOW, _FAST, _client, _rest


async def test_a_template_rooted_at_an_index_reads_a_json_array() -> None:
    """Hugging Face's Inference API answers ``[{"generated_text": ...}]``: a template whose
    ``text_path`` starts at an index reads that array, where the body was refused as not an
    object. Any other template still refuses an array."""

    adapter = RestAdapter(
        id="t1",
        base_url="https://api.example.test",
        allowlist=_ALLOW,
        template=RestTemplate(path="/generate", text_path="0.generated_text"),
        retry=_FAST,
        client=_client(json.dumps([{"generated_text": "hey"}]).encode(), []),
    )
    response = await adapter.send(ModelRequest(prompt="hi"))
    assert response.text == "hey"
    with pytest.raises(ResponseMalformed, match="not an object"):
        await _rest(json.dumps([{"output": "hey"}]).encode(), []).send(ModelRequest(prompt="hi"))
