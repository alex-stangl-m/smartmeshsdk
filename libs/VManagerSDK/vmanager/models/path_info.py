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


class PathInfo(object):
    """
    NOTE: This class is auto generated by the swagger code generator program.
    Do not edit the class manually.
    """
    def __init__(self):
        """
        PathInfo - a model defined in Swagger

        :param dict swaggerTypes: The key is attribute name
                                  and the value is attribute type.
        :param dict attributeMap: The key is attribute name
                                  and the value is json key in definition.
        """
        self.swagger_types = {
            'num_links': 'int',
            'quality': 'int',
            'rssi_ato_b': 'int',
            'rssi_bto_a': 'int'
        }

        self.attribute_map = {
            'num_links': 'numLinks',
            'quality': 'quality',
            'rssi_ato_b': 'rssiAtoB',
            'rssi_bto_a': 'rssiBtoA'
        }

        self._num_links = None
        self._quality = None
        self._rssi_ato_b = None
        self._rssi_bto_a = None

    @property
    def num_links(self):
        """
        Gets the num_links of this PathInfo.
        Number of upstream links on this path

        :return: The num_links of this PathInfo.
        :rtype: int
        """
        return self._num_links

    @num_links.setter
    def num_links(self, num_links):
        """
        Sets the num_links of this PathInfo.
        Number of upstream links on this path

        :param num_links: The num_links of this PathInfo.
        :type: int
        """
        self._num_links = num_links

    @property
    def quality(self):
        """
        Gets the quality of this PathInfo.
        An internal estimate of path quality based on a moving average of packets received over packets transmitted, in percent. Range is 0 (worst) to 100 (best). If no information about the path is available, quality is estimated based on the RSSI measured on the path

        :return: The quality of this PathInfo.
        :rtype: int
        """
        return self._quality

    @quality.setter
    def quality(self, quality):
        """
        Sets the quality of this PathInfo.
        An internal estimate of path quality based on a moving average of packets received over packets transmitted, in percent. Range is 0 (worst) to 100 (best). If no information about the path is available, quality is estimated based on the RSSI measured on the path

        :param quality: The quality of this PathInfo.
        :type: int
        """
        self._quality = quality

    @property
    def rssi_ato_b(self):
        """
        Gets the rssi_ato_b of this PathInfo.
        Latest RSSI on the path reported by device A, in dBm

        :return: The rssi_ato_b of this PathInfo.
        :rtype: int
        """
        return self._rssi_ato_b

    @rssi_ato_b.setter
    def rssi_ato_b(self, rssi_ato_b):
        """
        Sets the rssi_ato_b of this PathInfo.
        Latest RSSI on the path reported by device A, in dBm

        :param rssi_ato_b: The rssi_ato_b of this PathInfo.
        :type: int
        """
        self._rssi_ato_b = rssi_ato_b

    @property
    def rssi_bto_a(self):
        """
        Gets the rssi_bto_a of this PathInfo.
        Latest RSSI on the path reported by device B, in dBm

        :return: The rssi_bto_a of this PathInfo.
        :rtype: int
        """
        return self._rssi_bto_a

    @rssi_bto_a.setter
    def rssi_bto_a(self, rssi_bto_a):
        """
        Sets the rssi_bto_a of this PathInfo.
        Latest RSSI on the path reported by device B, in dBm

        :param rssi_bto_a: The rssi_bto_a of this PathInfo.
        :type: int
        """
        self._rssi_bto_a = rssi_bto_a

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

