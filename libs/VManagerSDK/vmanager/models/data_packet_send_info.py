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


class DataPacketSendInfo(object):
    """
    NOTE: This class is auto generated by the swagger code generator program.
    Do not edit the class manually.
    """
    def __init__(self):
        """
        DataPacketSendInfo - a model defined in Swagger

        :param dict swaggerTypes: The key is attribute name
                                  and the value is attribute type.
        :param dict attributeMap: The key is attribute name
                                  and the value is json key in definition.
        """
        self.swagger_types = {
            'dest_port': 'int',
            'payload': 'bytearray',
            'priority': 'str',
            'src_port': 'int'
        }

        self.attribute_map = {
            'dest_port': 'destPort',
            'payload': 'payload',
            'priority': 'priority',
            'src_port': 'srcPort'
        }

        self._dest_port = None
        self._payload = None
        self._priority = None
        self._src_port = None

    @property
    def dest_port(self):
        """
        Gets the dest_port of this DataPacketSendInfo.
        UDP destination port

        :return: The dest_port of this DataPacketSendInfo.
        :rtype: int
        """
        return self._dest_port

    @dest_port.setter
    def dest_port(self, dest_port):
        """
        Sets the dest_port of this DataPacketSendInfo.
        UDP destination port

        :param dest_port: The dest_port of this DataPacketSendInfo.
        :type: int
        """
        self._dest_port = dest_port

    @property
    def payload(self):
        """
        Gets the payload of this DataPacketSendInfo.
        Packet payload, in base64 format

        :return: The payload of this DataPacketSendInfo.
        :rtype: bytearray
        """
        return self._payload

    @payload.setter
    def payload(self, payload):
        """
        Sets the payload of this DataPacketSendInfo.
        Packet payload, in base64 format

        :param payload: The payload of this DataPacketSendInfo.
        :type: bytearray
        """
        self._payload = payload

    @property
    def priority(self):
        """
        Gets the priority of this DataPacketSendInfo.
        Packet priority

        :return: The priority of this DataPacketSendInfo.
        :rtype: str
        """
        return self._priority

    @priority.setter
    def priority(self, priority):
        """
        Sets the priority of this DataPacketSendInfo.
        Packet priority

        :param priority: The priority of this DataPacketSendInfo.
        :type: str
        """
        allowed_values = ["low", "medium", "high"]
        if priority not in allowed_values:
            raise ValueError(
                "Invalid value for `priority`, must be one of {0}"
                .format(allowed_values)
            )
        self._priority = priority

    @property
    def src_port(self):
        """
        Gets the src_port of this DataPacketSendInfo.
        UDP source port

        :return: The src_port of this DataPacketSendInfo.
        :rtype: int
        """
        return self._src_port

    @src_port.setter
    def src_port(self, src_port):
        """
        Sets the src_port of this DataPacketSendInfo.
        UDP source port

        :param src_port: The src_port of this DataPacketSendInfo.
        :type: int
        """
        self._src_port = src_port

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

