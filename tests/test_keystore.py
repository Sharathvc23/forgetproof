import pytest

from forgetproof import keystore


class _FakeKeyringError(Exception):
    pass


class _FakeErrors:
    KeyringError = _FakeKeyringError


class _FakeKeyring:
    """An in-memory stand-in: real backends aren't assumed to exist (most CI runners and
    headless dev machines have none), and a real one must never be touched by a test — on
    some platforms a first-ever access can pop an interactive unlock prompt."""

    def __init__(self):
        self.store: dict[tuple[str, str], str] = {}
        self.errors = _FakeErrors()

    def get_password(self, service, name):
        return self.store.get((service, name))

    def set_password(self, service, name, value):
        self.store[(service, name)] = value


class _AlwaysFailsKeyring(_FakeKeyring):
    def get_password(self, service, name):
        raise self.errors.KeyringError("no backend available")

    def set_password(self, service, name, value):
        raise self.errors.KeyringError("no backend available")


@pytest.fixture(autouse=True)
def isolated_env(monkeypatch):
    monkeypatch.delenv("FORGETPROOF_USE_KEYRING", raising=False)


def test_disabled_by_default_uses_the_file_even_with_a_working_backend(tmp_path, monkeypatch):
    fake = _FakeKeyring()
    monkeypatch.setattr(keystore, "keyring", fake)
    path = tmp_path / "secret.key"
    value = keystore.get_or_create("thing", path, lambda: b"generated-bytes")
    assert value == b"generated-bytes"
    assert path.read_bytes() == b"generated-bytes"
    assert fake.store == {}  # never touched: FORGETPROOF_USE_KEYRING wasn't set


def test_enabled_stores_in_the_keyring_not_the_file(tmp_path, monkeypatch):
    monkeypatch.setenv("FORGETPROOF_USE_KEYRING", "1")
    fake = _FakeKeyring()
    monkeypatch.setattr(keystore, "keyring", fake)
    path = tmp_path / "secret.key"

    value = keystore.get_or_create("thing", path, lambda: b"generated-bytes")
    assert value == b"generated-bytes"
    assert not path.exists()
    assert fake.store == {(keystore.SERVICE, "thing"): "generated-bytes".encode().hex()}

    # Second call returns the same secret from the keyring, without generating a new one or
    # ever creating the file.
    again = keystore.get_or_create("thing", path, lambda: (_ for _ in ()).throw(AssertionError("called again")))
    assert again == b"generated-bytes"
    assert not path.exists()


def test_an_existing_file_is_never_moved_into_the_keyring(tmp_path, monkeypatch):
    monkeypatch.setenv("FORGETPROOF_USE_KEYRING", "1")
    fake = _FakeKeyring()
    monkeypatch.setattr(keystore, "keyring", fake)
    path = tmp_path / "secret.key"
    path.write_bytes(b"pre-existing-file-key")

    value = keystore.get_or_create("thing", path, lambda: (_ for _ in ()).throw(AssertionError("called")))
    assert value == b"pre-existing-file-key"
    assert fake.store == {}  # untouched — turning the setting on didn't migrate anything


def test_a_keyring_error_falls_back_to_the_file(tmp_path, monkeypatch):
    monkeypatch.setenv("FORGETPROOF_USE_KEYRING", "1")
    monkeypatch.setattr(keystore, "keyring", _AlwaysFailsKeyring())
    path = tmp_path / "secret.key"
    value = keystore.get_or_create("thing", path, lambda: b"generated-bytes")
    assert value == b"generated-bytes"
    assert path.read_bytes() == b"generated-bytes"


def test_no_keyring_package_installed_falls_back_to_the_file(tmp_path, monkeypatch):
    monkeypatch.setenv("FORGETPROOF_USE_KEYRING", "1")
    monkeypatch.setattr(keystore, "keyring", None)  # simulates the [keyring] extra not being installed
    path = tmp_path / "secret.key"
    value = keystore.get_or_create("thing", path, lambda: b"generated-bytes")
    assert value == b"generated-bytes"
    assert path.read_bytes() == b"generated-bytes"


def test_file_is_created_owner_only_where_supported(tmp_path):
    path = tmp_path / "sub" / "secret.key"
    keystore.get_or_create("thing", path, lambda: b"x")
    mode = oct(path.stat().st_mode)[-3:]
    assert mode in ("600", "644", "666")  # best-effort; never asserted stricter on CI (e.g. Windows reports 666)


def test_receipt_signing_key_can_live_in_the_keyring(tmp_path, monkeypatch):
    from forgetproof import receipt

    monkeypatch.setenv("FORGETPROOF_HOME", str(tmp_path))
    monkeypatch.setenv("FORGETPROOF_USE_KEYRING", "1")
    monkeypatch.setattr(keystore, "keyring", _FakeKeyring())

    key = receipt.load_or_create_key()
    assert not receipt.key_path().exists()
    again = receipt.load_or_create_key()
    assert receipt.public_key_b64(again) == receipt.public_key_b64(key)  # same identity, not regenerated


def test_forget_queue_key_can_live_in_the_keyring(tmp_path, monkeypatch):
    from forgetproof import forget

    monkeypatch.setenv("FORGETPROOF_USE_KEYRING", "1")
    monkeypatch.setattr(keystore, "keyring", _FakeKeyring())

    qdir = tmp_path / "queue"
    qdir.mkdir()
    fernet = forget._queue_key(qdir)
    assert not (qdir / "queue.key").exists()
    token = fernet.encrypt(b"hello")
    assert forget._queue_key(qdir).decrypt(token) == b"hello"  # same key on a second call
