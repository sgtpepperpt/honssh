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

from twisted.conch.ssh import transport
from twisted.internet import protocol, defer
from honssh import log


class HonsshClientTransport(transport.SSHClientTransport):
    def connectionMade(self):
        log.msg(log.LGREEN, '[CLIENT]', 'New client connection')
        self.factory.server.client = self
        self.factory.server.sshParse.set_client(self)
        transport.SSHClientTransport.connectionMade(self)

    def verifyHostKey(self, pub_key, fingerprint):
        return defer.succeed(True)

    def connectionSecure(self):
        self.factory.server.clientConnected = True
        log.msg(log.LGREEN, '[CLIENT]', 'Client Connection Secured')

    def connectionLost(self, reason):
        transport.SSHClientTransport.connectionLost(self, reason)

        if self.factory.server.wasConnected:
            log.msg(log.LBLUE, '[CLIENT]',
                    'Lost connection with the Honeypot: ' + self.factory.server.sensor_name + ' (' + self.factory.server.honey_ip + ':' + str(
                        self.factory.server.honey_port) + ')')
        else:
            log.msg(log.LBLUE, '[CLIENT]', 'Lost connection with the Honeypot (Server<->Honeypot not connected)')

        if self.factory.server.post_auth_started:
            self.factory.server.pre_auth.connection_lost()
        else:
            self.factory.server.post_auth.connection_lost()

    def dispatchMessage(self, message_num, payload):
        if transport.SSHClientTransport.isEncrypted(self, "both"):
            self.factory.server.sshParse.parse_packet('[CLIENT]', message_num, payload)
        else:
            transport.SSHClientTransport.dispatchMessage(self, message_num, payload)


class HonsshClientFactory(protocol.ClientFactory):
    protocol = HonsshClientTransport
