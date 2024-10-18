import logging
from abc import ABC, abstractmethod
import pymongo
import bson


class AuthorizerInterface(ABC):
    @abstractmethod
    def initiate_user_group(self, username, groups):
        """
        Initiate a new user group.
        :param username: The username to associate with the new group.
        :param groups: The groups to be associated with the user.
        """
        pass

    @abstractmethod
    def update_user_group(self, username, groups):
        """
        Update an existing user's group.
        :param username: The username whose groups are to be updated.
        :param groups: The new groups to be associated with the user.
        """
        pass

    @abstractmethod
    def initiate_user_space(self, username):
        """
        Initiate a new user space.
        :param username: The username to associate with the new space.
        """
        pass

    @abstractmethod
    def update_user_space(self, username, privileges):
        """
        Update an existing user's space.
        :param username: The username whose space is to be updated.
        :param privileges: The new privileges to be associated with the user.
        """
        pass

    @abstractmethod
    def initiate_user_quota(self, username, quota):
        """
        Initiate a new user with quota.
        :param username: The username to associate with the new quota.
        :param quota: The quota to be assigned to the user.
        """
        pass

    @abstractmethod
    def update_user_quota(self, username, quota):
        """
        Update an existing user's quota.
        :param username: The username whose quota is to be updated.
        :param quota: The new quota to be assigned to the user.
        """
        pass

    @abstractmethod
    def check_authorization(self, user_info, requested_resource, protected_resource, allowed_groups, allowed_roles):
        """
        Check if the user is authorized to access the requested resource.
        :param user_info:
        :param requested_resource:
        :param protected_resource:
        :param allowed_groups:
        :param allowed_roles:
        :return:
        """
        pass


class IncoreAuthorizer(AuthorizerInterface):
    def __init__(self, mongodb_uri:str, mongo_client=None):
        if mongo_client:
            self.mongo_client = mongo_client
        else:
            self.mongo_client = pymongo.MongoClient(mongodb_uri)

    def initiate_user_group(self, username, groups):
        mongo_user = self.mongo_client["spacedb"]["UserGroups"].find_one({"username": username})
        if not mongo_user:
            self.mongo_client["spacedb"]["UserGroups"].insert_one({
                "username": username,
                "className": "edu.illinois.ncsa.incore.common.models.UserGroups",
                "groups": groups
            })
            logging.info(f"Inserted groups document for {username}")
            return True
        else:
            logging.info(f"Groups for {username} already exist")
            return False

    def update_user_group(self, username, groups):
        mongo_user = self.mongo_client["spacedb"]["UserGroups"].find_one({"username": username})
        if mongo_user and set(groups) != set(mongo_user["groups"]):
            self.mongo_client["spacedb"]["UserGroups"].update_one(
                {"username": username}, {"$set": {"groups": groups}}
            )
            logging.info(f"Synced groups for {username} - {groups}")
            return True
        else:
            logging.info(f"Groups for {username} already synced")
            return False

    def initiate_user_space(self, username):
        mongo_space = self.mongo_client["spacedb"]["Space"].find_one({"metadata.name": username})
        if not mongo_space:
            self.mongo_client["spacedb"]["Space"].insert_one({
                "className": "edu.illinois.ncsa.incore.common.models.Space",
                "metadata": {
                    "className": "edu.illinois.ncsa.incore.common.models.SpaceMetadata",
                    "name": username
                },
                "privileges": {
                    "className": "edu.illinois.ncsa.incore.common.auth.Privileges",
                    "userPrivileges": {
                        username: "ADMIN"
                    }
                },
                "members": [
                ]
            })
            logging.info(f"Inserted space document for {username}")
            return True
        else:
            logging.info(f"Space for {username} already exists")
            return False

    def update_user_space(self, username, privileges=None):
        mongo_space = self.mongo_client["spacedb"]["Space"].find_one({"metadata.name": username})
        if not mongo_space:
            self.mongo_client["spacedb"]["Space"].update_one({
                "metadata.name": username, "privileges.userPrivileges": privileges
            })
            logging.info(f"Update space for {username} - {privileges}")
            return True
        else:
            logging.info(f"Space for {username} doesn't exist. Please initiate first.")
            return False

    def initiate_user_quota(self, username, quota=None):
        mongo_usage = self.mongo_client["spacedb"]["UserAllocations"].find_one({"username": username})
        if not mongo_usage:
            self.mongo_client["spacedb"]["UserAllocations"].insert_one({
                "className": "edu.illinois.ncsa.incore.common.models.UserAllocations",
                "username": username,
                "usage": {
                    "className": "edu.illinois.ncsa.incore.common.models.UserUsages",
                    "datasets": int(0),
                    "hazards": int(0),
                    "hazardDatasets": int(0),
                    "dfr3": int(0),
                    "datasetSize": bson.Int64(0),
                    "hazardDatasetSize": bson.Int64(0)
                }
            })
            logging.info(f"Inserted usage document for {username}")
            return True
        else:
            logging.info(f"Usage for {username} already exists")
            return False

    def update_user_quota(self, username, quota=None):
        mongo_usage = self.mongo_client["spacedb"]["UserAllocations"].find_one({"username": username})
        if mongo_usage:
            self.mongo_client["spacedb"]["UserAllocations"].update_one(
                {"username": username}, {"$set": {"limits": quota}}
            )
            logging.info(f"Update quota for {username} - {quota}")
            return True
        else:
            logging.info(f"Quota for {username} doesn't exist. Please initiate first.")
            return False

    def check_authorization(self, user_info, requested_resource, protected_resource, allowed_groups, allowed_roles):
        authorized_groups = False
        authorized_roles = False
        if requested_resource in protected_resource:
            for group in user_info['groups']:
                if group in allowed_groups:
                    authorized_groups = True
                    break
            for role in user_info['roles']:
                if role in allowed_roles:
                    authorized_roles = True
                    break
        else:
            logging.debug("Unprotected resource.Access granted.")
            authorized_groups = True
            authorized_roles = True

        if not authorized_groups:
            logging.debug("group not found in user_accessible_resources")
        if not authorized_roles:
            logging.debug("role not found in user_accessible_resources")

        return authorized_roles and authorized_groups
