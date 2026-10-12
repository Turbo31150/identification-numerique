import tempfile
from pathlib import Path
from identification_numerique.core import SovereignIdentityManager, parse_ttl

def test_parse_ttl():
    assert parse_ttl("30d") == 30 * 86400
    assert parse_ttl("24h") == 24 * 3600
    assert parse_ttl("60m") == 3600
    assert parse_ttl("0") == 0

def test_create_and_verify():
    with tempfile.TemporaryDirectory() as tmpdir:
        storage = Path(tmpdir) / "identities.json"
        mgr = SovereignIdentityManager(storage_path=storage)
        
        token, record = mgr.create_identity("Client Test", scope="orbe", ttl="1d")
        assert token.startswith("id_sec_")
        assert record.label == "Client Test"
        
        # Test valid token
        res = mgr.verify(token, required_scope="orbe")
        assert res.valid is True
        assert res.record.label == "Client Test"

        # Test invalid token
        res_fake = mgr.verify("fake_token_123")
        assert res_fake.valid is False

        # Test scope mismatch
        res_scope = mgr.verify(token, required_scope="admin")
        assert res_scope.valid is False

        # Test revoke
        ok = mgr.revoke(record.id)
        assert ok is True
        res_revoked = mgr.verify(token)
        assert res_revoked.valid is False
        assert "révoquée" in res_revoked.reason
