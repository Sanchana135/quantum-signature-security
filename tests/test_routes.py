def test_public_pages(client):
    """Verify that public landing page and about page load without authentication."""
    res_index = client.get("/")
    assert res_index.status_code == 200
    assert b"Quantum-Inspired Cyber Threat Detection" in res_index.data

    res_about = client.get("/about")
    assert res_about.status_code == 200
    assert b"Mathematical Formulation" in res_about.data


def test_protected_routes_redirect_unauthenticated(client):
    """Verify that protected consoles redirect unauthenticated requests to login."""
    protected_urls = ["/dashboard", "/verify", "/demo-signer", "/analysis", "/events", "/auth/profile"]
    for url in protected_urls:
        res = client.get(url)
        assert res.status_code == 302
        assert "/auth/login" in res.headers["Location"]


def test_authenticated_access_to_consoles(auth_client):
    """Verify that authenticated analyst can load all application pages."""
    protected_urls = [
        ("/dashboard", b"Quantum Cyber Threat Dashboard"),
        ("/verify", b"Digital Signature Verification"),
        ("/demo-signer", b"Demo Key Generator"),
        ("/analysis", b"Threat Simulator"),
        ("/events", b"Security Audit Event Trail"),
        ("/auth/profile", b"Analyst Profile"),
    ]

    for url, expected_text in protected_urls:
        res = auth_client.get(url)
        assert res.status_code == 200, f"Failed accessing {url}"
        assert expected_text in res.data


def test_custom_404_page(client):
    """Verify that nonexistent URLs return custom 404 page."""
    res = client.get("/nonexistent-endpoint-404")
    assert res.status_code == 404
    assert b"404" in res.data
    assert b"Security Endpoint Not Found" in res.data
