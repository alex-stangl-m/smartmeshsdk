# coding: utf-8

"""
Copyright 2015 SmartBear Software

    Licensed under the Apache License, Version 2.0 (the "License");
    you may not use this file except in compliance with the License.
    You may obtain a copy of the License at

        http://www.apache.org/licenses/LICENSE-2.0

    Unless required by applicable law or agreed to in writing, software
    distributed under the License is distributed on an "AS IS" BASIS,
    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
    See the License for the specific language governing permissions and
    limitations under the License.

    Ref: https://github.com/swagger-api/swagger-codegen
"""

from pprint import pformat
from six import iteritems


class UserInfo(object):
    """
    NOTE: This class is auto generated by the swagger code generator program.
    Do not edit the class manually.
    """
    def __init__(self):
        """
        UserInfo - a model defined in Swagger

        :param dict swaggerTypes: The key is attribute name
                                  and the value is attribute type.
        :param dict attributeMap: The key is attribute name
                                  and the value is json key in definition.
        """
        self.swagger_types = {
            'description': 'str',
            'privilege': 'str',
            'user_id': 'str'
        }

        self.attribute_map = {
            'description': 'description',
            'privilege': 'privilege',
            'user_id': 'userId'
        }

        self._description = None
        self._privilege = None
        self._user_id = None

    @property
    def description(self):
        """
        Gets the description of this UserInfo.
        Text description of the user

        :return: The description of this UserInfo.
        :rtype: str
        """
        return self._description

    @description.setter
    def description(self, description):
        """
        Sets the description of this UserInfo.
        Text description of the user

        :param description: The description of this UserInfo.
        :type: str
        """
        self._description = description

    @property
    def privilege(self):
        """
        Gets the privilege of this UserInfo.
        User privilege

        :return: The privilege of this UserInfo.
        :rtype: str
        """
        return self._privilege

    @privilege.setter
    def privilege(self, privilege):
        """
        Sets the privilege of this UserInfo.
        User privilege

        :param privilege: The privilege of this UserInfo.
        :type: str
        """
        allowed_values = ["viewer", "user"]
        if privilege not in allowed_values:
            raise ValueError(
                "Invalid value for `privilege`, must be one of {0}"
                .format(allowed_values)
            )
        self._privilege = privilege

    @property
    def user_id(self):
        """
        Gets the user_id of this UserInfo.
        unique user identifier

        :return: The user_id of this UserInfo.
        :rtype: str
        """
        return self._user_id

    @user_id.setter
    def user_id(self, user_id):
        """
        Sets the user_id of this UserInfo.
        unique user identifier

        :param user_id: The user_id of this UserInfo.
        :type: str
        """
        self._user_id = user_id

    def to_dict(self):
        """
        Returns the model properties as a dict
        """
        result = {}

        for attr, _ in iteritems(self.swagger_types):
            value = getattr(self, attr)
            if isinstance(value, list):
                result[attr] = list([x.to_dict() if hasattr(x, "to_dict") else x for x in value])
            elif hasattr(value, "to_dict"):
                result[attr] = value.to_dict()
            else:
                result[attr] = value

        return result

    def to_str(self):
        """
        Returns the string representation of the model
        """
        return pformat(self.to_dict())

    def __repr__(self):
        """
        For `print` and `pprint`
        """
        return self.to_str()

    def __eq__(self, other): 
        """
        Returns true if both objects are equal
        """
        return self.__dict__ == other.__dict__

    def __ne__(self, other):
        """ 
        Returns true if both objects are not equal
        """
        return not self == other

