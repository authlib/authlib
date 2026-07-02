from authlib.tests.flask.test_oauth2.oauth2_server import create_flask_app, create_authorization_server
from authlib.integrations.flask_oauth2 import AuthorizationServer


def test_integration_authorize_prompt_create(monkeypatch):
    app = create_flask_app()
    server = create_authorization_server(app)

    client = app.test_client()
    # Simulate an authorization request with prompt=create
    resp = client.get('/oauth/authorize?response_type=code&client_id=1&redirect_uri=https%3A%2F%2Fclient.test%2Fcb&scope=openid&prompt=create')
    assert resp.status_code == 200
    # The authorize view in tests returns grant.prompt for GET
    assert resp.get_data(as_text=True) == 'create'
