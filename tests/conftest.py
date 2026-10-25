import pytest
from app import create_app
from app.models import db, User
from app.crypto.rsa_engine import generate_rsa_keypair

class UserData:
    def __init__(self, uid, username, email, role):
        self.id = uid
        self.username = username
        self.email = email
        self.role = role

@pytest.fixture
def app():
    """Create and configure a clean testing app instance."""
    app = create_app("testing")
    with app.app_context():
        db.create_all()
        yield app
        db.session.remove()
        db.drop_all()

@pytest.fixture
def client(app):
    """Test client without active session."""
    return app.test_client()

@pytest.fixture
def test_user(app):
    """Creates a standard test analyst user."""
    with app.app_context():
        user = User(
            username="test_analyst",
            email="test_analyst@quantum-shield.local",
            role="analyst"
        )
        user.set_password("SecurePass#2026!")
        db.session.add(user)
        db.session.commit()
        return UserData(user.id, user.username, user.email, user.role)

@pytest.fixture
def auth_client(client, test_user):
    """Client with authenticated session for test_analyst."""
    with client.session_transaction() as sess:
        sess["user_id"] = test_user.id
        sess["_csrf_token"] = "valid-token"
    return client

@pytest.fixture(scope="session")
def sample_rsa_pair():
    """Generates an RSA-2048 keypair once per test session."""
    priv, pub = generate_rsa_keypair(key_size=2048)
    return {"private_key": priv, "public_key": pub}
