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
        headers={"Authorization": "bearer eyJhbGciOiJSUzI1NiIsInR5cCIgOiAiSldUIiwia2lkIiA6ICJQMElRWmtSQXVROW1XcEdxLWYzZTV4cDRmT0Y2TEZRZkNqYkNRRGFtdFBBIn0.eyJleHAiOjE3MzEwOTE3MjEsImlhdCI6MTczMTA5MTQyMSwianRpIjoiOWFkNThiZGQtYjVkMi00MDllLTg5Y2MtYTQ4ZmE0ZTU4M2ZiIiwiaXNzIjoiaHR0cHM6Ly9kYWNodWIubmNzYS5pbGxpbm9pcy5lZHUvYXV0aC9yZWFsbXMvZGFjaHViIiwiYXVkIjoiYWNjb3VudCIsInN1YiI6ImZjZTY3NzYwLTgxNDYtNGM1Yi04ZjM2LWVhMjgxYWNkY2E4OCIsInR5cCI6IkJlYXJlciIsImF6cCI6ImRhY2h1YiIsInNlc3Npb25fc3RhdGUiOiJhNTAwNTViOS1hNWQzLTQ1NjktYTI4OS1kZWE2YTMwYzhjNWEiLCJhY3IiOiIxIiwiYWxsb3dlZC1vcmlnaW5zIjpbImh0dHA6Ly9sb2NhbGhvc3Q6ODA4MCIsImh0dHA6Ly9sb2NhbGhvc3Q6MzAwMCJdLCJyZWFsbV9hY2Nlc3MiOnsicm9sZXMiOlsiZGVmYXVsdC1yb2xlcy1kYWNodWIiLCJvZmZsaW5lX2FjY2VzcyIsInVtYV9hdXRob3JpemF0aW9uIl19LCJyZXNvdXJjZV9hY2Nlc3MiOnsiYWNjb3VudCI6eyJyb2xlcyI6WyJtYW5hZ2UtYWNjb3VudCIsIm1hbmFnZS1hY2NvdW50LWxpbmtzIiwidmlldy1wcm9maWxlIl19fSwic2NvcGUiOiJlbWFpbCBwcm9maWxlIiwic2lkIjoiYTUwMDU1YjktYTVkMy00NTY5LWEyODktZGVhNmEzMGM4YzVhIiwiZW1haWxfdmVyaWZpZWQiOmZhbHNlLCJuYW1lIjoiQ2hlbiBXYW5nIiwicHJlZmVycmVkX3VzZXJuYW1lIjoiY3dhbmcxMzgiLCJnaXZlbl9uYW1lIjoiQ2hlbiIsImZhbWlseV9uYW1lIjoiV2FuZyIsImVtYWlsIjoiY3dhbmcxMzhAaWxsaW5vaXMuZWR1In0.FhLamv2Tx8cBnR5wrOwcoUNBw6ca_Dwp0PJqmRKK6-opGF4nCTrizfo0a1uYulj5VEarVjhO6VrQ91mJnNcmrRbyuR_kjuQUq6A2TIN9XCEAu2lXpv71KfivTGeutxMGz6jSwRq0GszveZF0Kp34NWX5bwUZZ7OyXqk6rLK__yr6eSPZw5xwfB0dV7HmpmYlBkXH07EPq2Skqr6GIxaBWqrtA1Dg8IjMpZdX__mRoAlDGnyGMsyRfJleHsZHgJG9Tg4Yk-ehg252pfQ3rqQpgQ7pc-3SvWSradUd4OIpQBiY2Od2kLo7ltNGg_2y81R7ha0v4037LaYxFxmUNHQvag"}
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
    assert response.data == b"Unauthenticated"


def test_non_protected_resource(client):
    response = client.get("https://localhost:5000/test")

    assert response.status_code == 200
