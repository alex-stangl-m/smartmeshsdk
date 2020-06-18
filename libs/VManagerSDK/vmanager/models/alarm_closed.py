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


class AlarmClosed(object):
    """
    NOTE: This class is auto generated by the swagger code generator program.
    Do not edit the class manually.
    """
    def __init__(self):
        """
        AlarmClosed - a model defined in Swagger

        :param dict swaggerTypes: The key is attribute name
                                  and the value is attribute type.
        :param dict attributeMap: The key is attribute name
                                  and the value is json key in definition.
        """
        self.swagger_types = {
            'sys_time': 'datetime',
            'alarm_type': 'str',
            'type': 'str'
        }

        self.attribute_map = {
            'sys_time': 'sysTime',
            'alarm_type': 'alarmType',
            'type': 'type'
        }

        self._sys_time = None
        self._alarm_type = None
        self._type = None

    @property
    def sys_time(self):
        """
        Gets the sys_time of this AlarmClosed.
        Time of notification

        :return: The sys_time of this AlarmClosed.
        :rtype: datetime
        """
        return self._sys_time

    @sys_time.setter
    def sys_time(self, sys_time):
        """
        Sets the sys_time of this AlarmClosed.
        Time of notification

        :param sys_time: The sys_time of this AlarmClosed.
        :type: datetime
        """
        self._sys_time = sys_time

    @property
    def alarm_type(self):
        """
        Gets the alarm_type of this AlarmClosed.
        Alarm Type

        :return: The alarm_type of this AlarmClosed.
        :rtype: str
        """
        return self._alarm_type

    @alarm_type.setter
    def alarm_type(self, alarm_type):
        """
        Sets the alarm_type of this AlarmClosed.
        Alarm Type

        :param alarm_type: The alarm_type of this AlarmClosed.
        :type: str
        """
        allowed_values = ["maxMotesReached", "netTimeSync", "lostGPSSync"]
        if alarm_type not in allowed_values:
            raise ValueError(
                "Invalid value for `alarm_type`, must be one of {0}"
                .format(allowed_values)
            )
        self._alarm_type = alarm_type

    @property
    def type(self):
        """
        Gets the type of this AlarmClosed.
        Notification type

        :return: The type of this AlarmClosed.
        :rtype: str
        """
        return self._type

    @type.setter
    def type(self, type):
        """
        Sets the type of this AlarmClosed.
        Notification type

        :param type: The type of this AlarmClosed.
        :type: str
        """
        allowed_values = ["netStarted", "pathStateChanged", "pathAlert", "moteStateChanged", "joinFailed", "pingResponse", "invalidMIC", "dataPacketReceived", "ipPacketReceived", "packetSent", "cmdFinished", "configChanged", "configLoaded", "alarmOpened", "alarmClosed", "deviceHealthReport", "neighborHealthReport", "discoveryHealthReport", "rawMoteNotification", "serviceChanged", "apStateChanged", "managerStarted", "managerStopping", "optPhase", "pathAlert", "moteTrace", "frameCapacity", "apGpsSyncChanged"]
        if type not in allowed_values:
            raise ValueError(
                "Invalid value for `type`, must be one of {0}"
                .format(allowed_values)
            )
        self._type = type

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

