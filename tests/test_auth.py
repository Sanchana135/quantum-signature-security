from app.models import User

def test_user_registration_success(client, app):
    """Test standard valid user registration."""
    with client.session_transaction() as sess:
        sess["_csrf_token"] = "valid-token"

    response = client.post("/auth/register", data={
        "csrf_token": "valid-token",
        "username": "new_analyst",
        "email": "new_analyst@domain.com",
        "password": "ValidPass#123",
        "confirm_password": "ValidPass#123",
    }, follow_redirects=True)

    assert response.status_code == 200
    with app.app_context():
        user = User.query.filter_by(username="new_analyst").first()
        assert user is not None
        assert user.email == "new_analyst@domain.com"
        assert user.check_password("ValidPass#123")


def test_user_registration_duplicate_username(client, test_user):
    """Test duplicate username rejection."""
    with client.session_transaction() as sess:
        sess["_csrf_token"] = "valid-token"

    response = client.post("/auth/register", data={
        "csrf_token": "valid-token",
        "username": test_user.username,
        "email": "different_email@domain.com",
        "password": "ValidPass#123",
        "confirm_password": "ValidPass#123",
    }, follow_redirects=True)

    assert b"Username is already registered" in response.data


def test_user_registration_duplicate_email(client, test_user):
    """Test duplicate email rejection."""
    with client.session_transaction() as sess:
        sess["_csrf_token"] = "valid-token"

    response = client.post("/auth/register", data={
        "csrf_token": "valid-token",
        "username": "unique_username",
        "email": test_user.email,
        "password": "ValidPass#123",
        "confirm_password": "ValidPass#123",
    }, follow_redirects=True)

    assert b"Email address is already registered" in response.data


def test_user_registration_weak_passwords(client):
    """Test that passwords without symbols, digits, or length are rejected."""
    with client.session_transaction() as sess:
        sess["_csrf_token"] = "valid-token"

    # Too short
    res = client.post("/auth/register", data={
        "csrf_token": "valid-token",
        "username": "user1",
        "email": "user1@test.com",
        "password": "Sh1!",
        "confirm_password": "Sh1!",
    }, follow_redirects=True)
    assert b"at least 8 characters" in res.data

    # No number
    res = client.post("/auth/register", data={
        "csrf_token": "valid-token",
        "username": "user2",
        "email": "user2@test.com",
        "password": "NoNumberPassword!",
        "confirm_password": "NoNumberPassword!",
    }, follow_redirects=True)
    assert b"contain at least one number" in res.data

    # No special character
    res = client.post("/auth/register", data={
        "csrf_token": "valid-token",
        "username": "user3",
        "email": "user3@test.com",
        "password": "NoSpecialChar123",
        "confirm_password": "NoSpecialChar123",
    }, follow_redirects=True)
    assert b"special character" in res.data


def test_login_success(client, test_user):
    """Test successful login with correct credentials."""
    with client.session_transaction() as sess:
        sess["_csrf_token"] = "valid-token"

    res = client.post("/auth/login", data={
        "csrf_token": "valid-token",
        "username": test_user.username,
        "password": "SecurePass#2026!",
    }, follow_redirects=True)

    assert res.status_code == 200
    with client.session_transaction() as sess:
        assert sess.get("user_id") == test_user.id


def test_login_invalid_password_masked(client, test_user):
    """Test that wrong password returns generic masked message."""
    with client.session_transaction() as sess:
        sess["_csrf_token"] = "valid-token"

    res = client.post("/auth/login", data={
        "csrf_token": "valid-token",
        "username": test_user.username,
        "password": "WrongPassword#999",
    }, follow_redirects=True)

    assert b"Invalid username or password" in res.data
    with client.session_transaction() as sess:
        assert sess.get("user_id") is None


def test_logout(auth_client):
    """Test logout clears session."""
    res = auth_client.get("/auth/logout", follow_redirects=True)
    assert res.status_code == 200
    with auth_client.session_transaction() as sess:
        assert sess.get("user_id") is None
