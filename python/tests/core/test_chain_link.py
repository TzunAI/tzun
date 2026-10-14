import hashlib

from tzun_sdk._generated.chain import compute_chain_link


def test_genesis_link_is_none():
    assert compute_chain_link(None, "cur") is None

def test_link_is_sha256_prev_plus_cur_bare_hex():
    expected = hashlib.sha256(("prev" + "cur").encode("utf-8")).hexdigest()
    assert compute_chain_link("prev", "cur") == expected
    assert ":" not in compute_chain_link("prev", "cur")
