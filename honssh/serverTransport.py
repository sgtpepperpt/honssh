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

from twisted.conch.ssh import factory
from twisted.internet import reactor

from honssh import honsshServer
from honssh import log
from honssh import post_auth_handler
from honssh import pre_auth_handler
from honssh.protocols import ssh


class HonsshServerTransport(honsshServer.HonsshServer):
    def __init__(self):
        self.timeoutCount = 0
        self.interactors = []

        self.sshParse = None

        self.wasConnected = False
        self.disconnected = False
        self.clientConnected = False
        self.post_auth_started = False
        self.spoofed = False

        self.peer_ip = None
        self.peer_port = 0
        self.local_ip = None
        self.local_port = 0

        self.pre_auth = None
        self.post_auth = None

        self.sensor_name = None
        self.honey_ip = None
        self.honey_port = 0

    def connectionMade(self):
        self.sshParse = ssh.SSH(self)

        self.peer_ip = self.transport.getPeer().host
        self.peer_port = self.transport.getPeer().port + 1
        self.local_ip = self.transport.getHost().host
        self.local_port = self.transport.getHost().port

        self.pre_auth = pre_auth_handler.PreAuth(self)
        self.post_auth = post_auth_handler.PostAuth(self)

        # Execute pre auth
        self.pre_auth.start()

        honsshServer.HonsshServer.connectionMade(self)

    def connectionLost(self, reason):
        try:
            self.client.loseConnection()
        except:
            pass
        honsshServer.HonsshServer.connectionLost(self, reason)

    def ssh_KEXINIT(self, packet):
        return honsshServer.HonsshServer.ssh_KEXINIT(self, packet)

    def dispatchMessage(self, message_num, payload):
        if honsshServer.HonsshServer.isEncrypted(self, "both"):
            if not self.post_auth_started:
                self.packet_buffer(self.pre_auth, message_num, payload)
            else:
                self.packet_buffer(self.post_auth, message_num, payload)
        else:
            honsshServer.HonsshServer.dispatchMessage(self, message_num, payload)

    def packet_buffer(self, stage, message_num, payload):
        if not self.clientConnected:
            log.msg(log.LPURPLE, '[SERVER]', 'CONNECTION TO HONEYPOT NOT READY, BUFFERING PACKET')
            stage.delayedPackets.append([message_num, payload])
        else:
            if not stage.finishedSending:
                stage.delayedPackets.append([message_num, payload])
            else:
                self.sshParse.parse_packet("[SERVER]", message_num, payload)

    def sendPacket(self, message_num, payload):
        honsshServer.HonsshServer.sendPacket(self, message_num, payload)

    def connection_init(self, sensor_name, honey_ip, honey_port):
        self.sensor_name = sensor_name
        self.honey_ip = honey_ip
        self.honey_port = honey_port

    def connection_setup(self):
        self.wasConnected = True

    def start_post_auth(self, username, password, auth_type):
        self.post_auth_started = True
        self.post_auth.start(username, password, auth_type)

    def login_successful(self, username, password):
        self.post_auth.login_successful()

    def login_failed(self, username, password):
        self.post_auth.login_failed()


class HonsshServerFactory(factory.SSHFactory):
    def __init__(self):
        self.otherVersionString = ''
        self.plugin_servers = []
        self.ourVersionString = 'SSH-2.0-OpenSSH_7.6p1 Ubuntu-4ubuntu0.3'

        self.plugin_servers.append({'name': 'honeypot-static', 'server': False})

        if self.ourVersionString != '':
            log.msg(log.LGREEN, '[HONSSH]', 'HonSSH Boot Sequence Complete - Ready for attacks!')

    def buildProtocol(self, addr):
        t = HonsshServerTransport()

        t.ourVersionString = self.ourVersionString
        t.factory = self
        t.supportedPublicKeys = self.privateKeys.keys()

        if not self.primes:
            ske = t.supportedKeyExchanges[:]
            if 'diffie-hellman-group-exchange-sha1' in ske:
                ske.remove('diffie-hellman-group-exchange-sha1')
            if 'diffie-hellman-group-exchange-sha256' in ske:
                ske.remove('diffie-hellman-group-exchange-sha256')
            t.supportedKeyExchanges = ske

        t.supportedCiphers = ['aes128-ctr', 'aes192-ctr', 'aes256-ctr', 'aes128-cbc', '3des-cbc', 'blowfish-cbc',
                              'cast128-cbc', 'aes192-cbc', 'aes256-cbc']
        t.supportedPublicKeys = ['ssh-rsa', 'ssh-dss']
        t.supportedMACs = ['hmac-md5', 'hmac-sha1']
        return t