import json
import os
from urllib.parse import unquote_plus

from flask import Flask, request, Response, make_response
from dotenv import load_dotenv

from authenticator import JWTAuthenticator
from util import Util

# Load environment variables from .env file
load_dotenv()

# Load configuration from JSON file
with open("config.json") as config_file:
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
    if request.url_rule is None:
        return healthz()

    # Handle CORS preflight
    if request.headers.get('X-Forwarded-Method') == 'OPTIONS':
        return Response(status=200)

    # Retrieve user and request information
    request_info = Util.get_request_info(request)['resource']

    # Allow non-protected resources
    if request_info['resource'] not in app.config["PROTECTED_RESOURCES"]:
        return Response(status=200)

    # Authentication check
    if jwt_authenticator.verify_token(request.headers.get('Authorization', '')):
        user_info = jwt_authenticator.get_userinfo(request.headers.get('Authorization', ''))

        # Build response
        response = Response(status=200)
        response.headers['X-Auth-UserInfo'] = json.dumps({"preferred_username": user_info['username']})
        response.headers['X-Auth-UserGroup'] = json.dumps({"groups": user_info['groups']})

        # Handle Authorization headers and cookies
        auth_header = request.headers.get('Authorization') or request.cookies.get('Authorization')
        if auth_header:
            response.headers['Authorization'] = unquote_plus(auth_header)

        group_header = request.headers.get('X-Auth-UserGroup') or request.cookies.get('X-Auth-UserGroup')
        if group_header:
            response.headers['X-Auth-UserGroup'] = group_header

        return response

    else:
        return make_response("Unauthenticated", 401)


@app.route("/healthz", methods=["GET"])
def healthz():
    """Health check endpoint."""
    return Response("OK", 200)

# Uncomment to run locally
# if __name__ == "__main__":
#     app.run(host="0.0.0.0", port=5000, debug=True)
