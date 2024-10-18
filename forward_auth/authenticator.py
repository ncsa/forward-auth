import logging
from abc import ABC, abstractmethod
from jose import jwt
from jose.exceptions import JWTError, ExpiredSignatureError, JWTClaimsError
import time

from util import Util


class AuthenticatorInterface(ABC):
    """
    Interface for the Authenticator object
    """

    @abstractmethod
    def get_public_key(self):
        pass

    @abstractmethod
    def verify_token(self, token):
        pass

    @abstractmethod
    def get_userinfo(self, token):
        pass


class JWTAuthenticator(AuthenticatorInterface):
    """
    JWT Authenticator class that implements the AuthenticatorInterface
    """

    def __init__(self, audience, pem_key, issuer_url=None):
        self.pem_key = pem_key
        self.issuer_url = issuer_url
        self.audience = audience

    def get_public_key(self):
        # if PEM key not provided through instantiation
        # might be endpoint that provide PEM key
        if self.pem_key is not None:
            pem_key = str(self.pem_key)
        elif self.issuer_url is not None:
            result = Util.urljson(self.issuer_url)
            pem_key = result.get("public_key", None)
        else:
            pem_key = None

        if pem_key is None:
            logging.error("Could not find PEM, things will be broken.")
            return None

        return f"-----BEGIN PUBLIC KEY-----\n" \
               f"{pem_key}\n" \
               f"-----END PUBLIC KEY-----"

    def verify_token(self, token):
        # decode token for validating its signature
        try:
            public_key = self.get_public_key()
            if public_key is not None:
                decoded_token = jwt.decode(token, self.get_public_key(), audience=self.audience)
            else:
                logging.debug("Could not get public key")
                return False, "Error: missing valid public key"
        except ExpiredSignatureError:
            logging.debug("token signature has expired")
            return False, "JWT Expired Signature Error: token signature has expired"
        except JWTClaimsError:
            logging.debug("toke signature has invalid claim")
            return False, "JWT Claims Error: token signature is invalid"
        except JWTError:
            logging.debug("jwt error")
            return False, "JWT Error: token is invalid"
        except Exception:
            logging.debug("random exception")
            return False, "Error: cannot verify token"
        return True, decoded_token

    def get_userinfo(self, token):
        user_info = {
            "username": "",
            "firstname": "",
            "lastname": "",
            "fullname": "",
            "resource": "",
            "groups": [],
            "roles": [],
            "start": time.time()
        }
        valid, decoded_token = self.verify_token(token)
        if valid:
            user_info["username"] = decoded_token["preferred_username"]
            user_info["firstname"] = decoded_token["given_name"]
            user_info["lastname"] = decoded_token["family_name"]
            user_info["fullname"] = decoded_token["name"]
            user_info["groups"] = decoded_token.get("groups", [])
            if "roles" in decoded_token:
                user_info["roles"] = decoded_token["roles"]
            elif "realm_access" in decoded_token:
                user_info["roles"] = decoded_token["realm_access"].get("roles", [])
            else:
                user_info["roles"] = []

        return user_info
