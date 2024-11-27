import json
import os
from urllib.parse import unquote_plus

from flask import Flask, request, Response, make_response
from dotenv import load_dotenv

from forward_auth.authenticator import JWTAuthenticator
from forward_auth.util import Util

# Load environment variables from .env file
load_dotenv()

# Load configuration from JSON file
with open("./config.json") as config_file:
    config = json.load(config_file)

app = Flask(__name__)
app.config.from_mapping(config)

# Initialize services
jwt_authenticator = JWTAuthenticator(
    audience=os.getenv('KEYCLOAK_AUDIENCE'),
    pem_key=os.getenv('KEYCLOAK_PUBLIC_KEY'),
    issuer_url=os.getenv('KEYCLOAK_URL')
)


@app.before_request
def handle_request():
    """Handle incoming requests: authorization, resource checks, and monitoring."""
    if request.url_rule is not None:
        return healthz()

    # Handle CORS preflight
    if request.headers.get('X-Forwarded-Method') == 'OPTIONS' or request.method == 'OPTIONS':
        return Response(status=200)

    # Retrieve user and request information
    request_info = Util.get_request_info(request)

    # Allow non-protected resources
    if request_info['resource'] not in app.config["PROTECTED_RESOURCES"]:
        return Response(status=200)

    # Handle Authorization headers and cookies
    auth_header = request.headers.get('Authorization') or request.cookies.get('Authorization')
    if auth_header:
        token = auth_header.split(" ")[1] if "bearer " in auth_header.lower() else auth_header
        if token.count('.') != 2:
            make_response("Invalid JWT format: Not enough segments.", 400)

        verified, message = jwt_authenticator.verify_token(token)
        if verified:
            user_info = jwt_authenticator.get_userinfo(token)

            # Build response
            response = Response(status=200)
            response.headers['X-Auth-UserInfo'] = json.dumps({"preferred_username": user_info['username']})
            response.headers['X-Auth-UserGroup'] = json.dumps({"groups": user_info['groups']})
            response.headers['Authorization'] = unquote_plus(auth_header)

            group_header = request.headers.get('X-Auth-UserGroup') or request.cookies.get('X-Auth-UserGroup')
            if group_header:
                response.headers['X-Auth-UserGroup'] = group_header

            return response
        else:
            return make_response(message, 401)
    else:
        return make_response("Unauthenticated", 401)


@app.route("/healthz", methods=["GET"])
def healthz():
    """Health check endpoint."""
    return Response("OK", 200)

# Uncomment to run locally
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
