
class ForwardAuth:

    def __init__(self, authenticator, authorizer, monitor):
        self.authenticator = authenticator
        self.authorizer = authorizer
        self.monitor = monitor

    def before_first_request(self):
        # Setup JWT Authenticator
        pem_key = self.authenticator.get_pem_key()
        issuer = self.authenticator.get_issuer()
        self.config['public_key'] = f"-----BEGIN PUBLIC KEY-----\n{pem_key}\n-----END PUBLIC KEY-----"
        self.config['issuer'] = issuer

        # Setup Geohash Monitor
        if self.monitor:
            self.monitor.setup()

    def setup():
        keycloak_pem = os.environ.get('KEYCLOAK_PUBLIC_KEY', None)
        if keycloak_pem:
            config['pem'] = str(keycloak_pem)
            app.logger.info("Got public_key from environment variable.")
        else:
            keycloak_url = os.environ.get('KEYCLOAK_URL', None)
            if keycloak_url:
                result = urljson(keycloak_url)
                config['pem'] = result['public_key']
                app.logger.info("Got public_key from url.")
            else:
                config['pem'] = ''
                app.logger.error("Could not find PEM, things will be broken.")

        config['public_key'] = f"-----BEGIN PUBLIC KEY-----\n" \
                               f"{config['pem']}\n" \
                               f"-----END PUBLIC KEY-----"

        keycloak_audience = os.environ.get('KEYCLOAK_AUDIENCE', None)
        if keycloak_audience:
            config['audience'] = keycloak_audience
        else:
            config['audience'] = None

        # store datawolf url
        config["datawolf_url"] = os.environ.get('DATAWOLF_URL', None)

        # setup mongodb
        mongodb_uri = os.environ.get('MONGODB_URI', None)
        if mongodb_uri:
            mongo_client = pymongo.MongoClient(mongodb_uri)
            config["mongo_client"] = mongo_client
        else:
            config["mongo_client"] = None

        # setup influxdb
        try:
            client = influxdb_client.InfluxDBClient.from_env_properties()
            writer = client.write_api()
            config['influxdb'] = writer
        except:
            app.logger.exception("Could not setup influxdb writer")
            config['influxdb'] = None
            pass

        def before_request(self):
            # Extract token and verify
            access_token = self.authenticator.verify_token(request.headers.get('Authorization'))
            if access_token:
                request_info = {"username": access_token.get("preferred_username")}

        def before_request(self):
            def verify_token():
                """
                This function distinguishes between requests that need authorization
                and verifies if those who need to be authorized contain the access
                token in its headers or cookies. If the token verification and user
                authorization was successful, it updates the headers, adding a
                user-info string.
                :return: HTTP response. 200 if path is not protected. 200 if path is
                protected and meets the following criteria: 1) request contains an
                Authorization header or cookie with bearer token. 2) The access
                token has a valid signature (not expired or invalid). 3) The user
                belongs to the appropriate group required to access the protected
                path. 401 if token is invalid or not present. 403 if token is
                present and valid but the user does not belong to the appropriate
                groups for the protected path.
                """
                # check if the url is for the /healthz route, in the future we might
                # need to check what is the actual rule
                if request.url_rule is not None:
                    return healthz()

                # allow options, probably CORS
                if request.headers.get('X-Forwarded-Method', '') == 'OPTIONS':
                    return Response(status=200)

                # dict to hold all information
                request_info = {
                    "username": "",
                    "firstname": "",
                    "lastname": "",
                    "fullname": "",
                    "method": request.method,
                    "url": request.path,
                    "resource": "",
                    "groups": [],
                    "roles": [],
                    "error": "",
                    "fields": {},
                    "tags": {},
                    "start": time.time()
                }

                # get info requested
                request_resource(request_info)
                request_userinfo(request_info)

                # update backend services
                update_services(request_info)

                # record request
                record_request(request_info)

                # non protected resource is always ok
                if request_info['resource'] not in app.config["PROTECTED_RESOURCES"]:
                    return Response(status=200)

                # check the authentication
                if not request_info['username']:
                    return make_response(request_info['error'], 401)

                # check the authorization
                authorized = False
                if "GROUPS" in app.config and not authorized:
                    for group in request_info['groups']:
                        if group in app.config["GROUPS"] and request_info['resource'] in app.config["GROUPS"][group]:
                            authorized = True
                            break
                if "ROLES" in app.config and not authorized:
                    for role in request_info['roles']:
                        if role in app.config["ROLES"] and request_info['resource'] in app.config["ROLES"][role]:
                            authorized = True
                            break
                if not authorized:
                    app.logger.debug("role not found in user_accessible_resources")
                    return make_response("access denied", 403)

                # everything is ok
                user_info = {"preferred_username": request_info['username']}
                group_info = {"groups": request_info['groups']}
                response = Response(status=200)
                response.headers['X-Auth-UserInfo'] = json.dumps(user_info)
                response.headers['X-Auth-UserGroup'] = json.dumps(group_info)

                if request.headers.get('Authorization') is not None:
                    response.headers['Authorization'] = unquote_plus(request.headers['Authorization'])
                elif request.cookies.get('Authorization') is not None:
                    response.headers['Authorization'] = unquote_plus(request.cookies['Authorization'])

                if request.headers.get('X-Auth-UserGroup') is not None:
                    response.headers['X-Auth-UserGroup'] = request.headers.get('X-Auth-UserGroup')
                elif request.cookies.get('X-Auth-UserGroup') is not None:
                    response.headers['X-Auth-UserGroup'] = request.cookies['X-Auth-UserGroup']

                return response
