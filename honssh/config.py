# Copyright (c) 2016 Thomas Nicholson <tnnich@googlemail.com>
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions
# are met:
#
# 1. Redistributions of source code must retain the above copyright
#    notice, this list of conditions and the following disclaimer.
# 2. Redistributions in binary form must reproduce the above copyright
#    notice, this list of conditions and the following disclaimer in the
#    documentation and/or other materials provided with the distribution.
# 3. The names of the author(s) may not be used to endorse or promote
#    products derived from this software without specific prior written
#    permission.
#
# THIS SOFTWARE IS PROVIDED BY THE AUTHORS ``AS IS'' AND ANY EXPRESS OR
# IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
# OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
# IN NO EVENT SHALL THE AUTHORS BE LIABLE FOR ANY DIRECT, INDIRECT,
# INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
# BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
# LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED
# AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
# OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
# OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
# SUCH DAMAGE.

import ConfigParser
import inspect

class Config(ConfigParser.ConfigParser):
    _instance = None

    @classmethod
    def getInstance(cls):
        if cls._instance is None:
            cls._instance = cls()

        return  cls._instance

    def __init__(self):
        stack = inspect.stack()

        if 'cls' in stack[1][0].f_locals and stack[1][0].f_locals['cls'] is self.__class__:
            ConfigParser.ConfigParser.__init__(self)

        else:
            raise Exception('This class cannot be instantiated from outside. Please use \'getInstance()\'')

    def validate_config(self):
        return True

    def check_exist(self, prop, validation_function=None):
        if self.has_option(prop[0], prop[1]):
            val = ConfigParser.ConfigParser.get(self, prop[0], prop[1])

            if len(val) > 0:
                if validation_function is None:
                    return True
                else:
                    if validation_function(prop, val):
                        return True
                    else:
                        return False
            else:
                print '[VALIDATION] - [' + prop[0] + '][' + prop[1] + '] must not be blank.'
                return False
        else:
            print '[VALIDATION] - [' + prop[0] + '][' + prop[1] + '] must exist.'
            return False

    def get(self, prop, raw=False, vars=None, default=None):
        if ConfigParser.ConfigParser.has_option(self, prop[0], prop[1]):
            ret = ConfigParser.ConfigParser.get(self, prop[0], prop[1], raw, vars)
        else:
            ret = ''

        if len(ret) == 0 and default is not None:
            ret = default

        return ret

    def _getconv(self, prop, conv=None, default=None):
        if ConfigParser.ConfigParser.has_option(self, prop[0], prop[1]):
            ret = ConfigParser.ConfigParser.get(self, prop[0], prop[1], False, None)
        else:
            ret = ''

        if len(ret) == 0 and default is not None:
            ret = default
        elif len(ret) > 0 and conv is not None:
            try:
                ret = conv(ret)
            except:
                pass

        return ret

    def getport(self, prop, default=None):
        return self._getconv(prop, int, default)

    def getip(self, prop, default=None):
        return self._getconv(prop, None, default)

    def getint(self, prop, default=None):
        return self._getconv(prop, int, default)

    def getfloat(self, prop, default=None):
        return self._getconv(prop, float, default)

    def getboolean(self, prop, default=False):
        val = self._getconv(prop, None, default)

        if val == 'true':
            return True
        else:
            return False
