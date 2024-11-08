import json
import os
import pytest
from unittest.mock import patch, MagicMock
from flask import Flask

from app import app  # Replace `your_app_module` with the module name of your app


@pytest.fixture
def client():
    app.config["TESTING"] = True
    with app.test_client() as client:
        yield client


def test_authorized_request(client):
    response = client.get(
        "https://localhost:5000/geoserver",  # Replace with an actual protected endpoint in your app
        headers={"Authorization": "bearer valid_token"}
    )

    assert response.status_code == 200
    assert response.headers["X-Auth-UserInfo"] == json.dumps({"preferred_username": "cwang138"})
    assert response.headers["X-Auth-UserGroup"] == json.dumps({"groups": []})


def test_unauthorized_request(client):
    response = client.get(
        "https://localhost:5000/geoserver",
        headers={"Authorization": "Bearer invalid_token"}
    )

    assert response.status_code == 401
    assert response.data == b"JWT Error: token is invalid"


def test_non_protected_resource(client):
    response = client.get("https://localhost:5000/test")

    assert response.status_code == 200
