import json
import threading
import os
from urllib.parse import unquote_plus

from flask import Flask, request, Response, make_response
from dotenv import load_dotenv
from cachetools import cached, TTLCache

from authenticator import JWTAuthenticator
from authorizer import IncoreAuthorizer
from monitor import IncoreMonitor
from util import Util

# Load environment variables from .env file
load_dotenv()

# Load configuration from JSON file
with open("config.json") as config_file:
    config = json.load(config_file)

app = Flask(__name__)
app.config.from_mapping(config)

# Constants for caching and services
CACHE_SIZE = 1024
CACHE_TIMEOUT = 30 * 60

# Initialize services
incore_authenticator = JWTAuthenticator(
    audience=os.getenv('KEYCLOAK_AUDIENCE'),
    pem_key=os.getenv('KEYCLOAK_PUBLIC_KEY'),
    issuer_url=os.getenv('KEYCLOAK_URL')
)
incore_authorizer = IncoreAuthorizer(
    mongodb_uri=os.getenv('MONGODB_URI'),
    datawolf_url=os.getenv('DATAWOLF_URL')
)
incore_monitor = IncoreMonitor(
    geolocation_db_name=os.getenv('INFLUXDB_V2_FILE_LOCATION', 'data/IP2LOCATION-LITE-DB5.BIN'),
    track_resources=(app.config["TRACKED_RESOURCES"])
)
incore_monitor.setup()

def update_services_thread(user_info):
    """Update user groups and DataWolf access in a separate thread."""
    incore_authorizer.add_datawolf_user(user_info)
    incore_authorizer.initiate_user_space(user_info["username"])
    incore_authorizer.initiate_user_quota(user_info["username"])
    incore_authorizer.initiate_user_group(user_info["username"], user_info["groups"])
    incore_authorizer.update_user_group(user_info["username"], user_info["groups"])


@cached(cache=TTLCache(maxsize=CACHE_SIZE, ttl=CACHE_TIMEOUT), key=Util.user_info_as_cache_key)
def update_services(request_info):
    threading.Thread(target=update_services_thread, args=(request_info,), daemon=True).start()


@app.before_request
def handle_request():
    """Handle incoming requests: authorization, resource checks, and monitoring."""
    if request.url_rule is None:
        return healthz()

    # Handle CORS preflight
    if request.headers.get('X-Forwarded-Method') == 'OPTIONS':
        return Response(status=200)

    # Retrieve user and request information
    request_info = incore_monitor.get_request_info(request)['resource']
    user_info = incore_authenticator.get_userinfo(request.headers.get('Authorization', ''))

    # Update backend services asynchronously
    update_services(request_info)

    # Record the request for monitoring purposes
    incore_monitor.record_request(request)

    # Allow non-protected resources
    if request_info['resource'] not in app.config["PROTECTED_RESOURCES"]:
        return Response(status=200)

    # Authentication check
    if not user_info.get('username'):
        return make_response(request_info.get('error', 'Unauthorized'), 401)

    # Authorization check
    authorized = incore_authorizer.check_authorization(
        user_info=user_info,
        requested_resource=request_info['resource'],
        protected_resources=app.config["PROTECTED_RESOURCES"],
        allowed_groups=app.config["GROUPS"],
        allowed_roles=app.config["ROLES"]
    )
    if not authorized:
        return make_response("Access Denied", 403)

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


@app.route("/healthz", methods=["GET"])
def healthz():
    """Health check endpoint."""
    return Response("OK", 200)

# Uncomment to run locally
# if __name__ == "__main__":
#     app.run(host="0.0.0.0", port=5000, debug=True)
