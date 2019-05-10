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

from twisted.conch.ssh import factory, transport

from honssh import log
from honssh import post_auth_handler
from honssh import pre_auth_handler
from honssh.protocols import ssh


class HonsshServerTransport(transport.SSHServerTransport):
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

        """
        Called when the connection is made to the other side.  We sent our
        version and the MSG_KEXINIT packet.
        """
        self.transport.write('%s\r\n' % (self.ourVersionString,))
        self.currentEncryptions = transport.SSHCiphers('none', 'none', 'none', 'none')
        self.currentEncryptions.setKeys('', '', '', '', '', '')
        self.otherVersionString = 'Unknown'

    def connectionLost(self, reason):
        try:
            self.client.loseConnection()
        except:
            pass
        transport.SSHServerTransport.connectionLost(self, reason)

    def dispatchMessage(self, message_num, payload):
        if transport.SSHServerTransport.isEncrypted(self, "both"):
            if not self.post_auth_started:
                self.packet_buffer(self.pre_auth, message_num, payload)
            else:
                self.packet_buffer(self.post_auth, message_num, payload)
        else:
            transport.SSHServerTransport.dispatchMessage(self, message_num, payload)

    def packet_buffer(self, stage, message_num, payload):
        if not self.clientConnected:
            log.msg(log.LPURPLE, '[SERVER]', 'CONNECTION TO HONEYPOT NOT READY, BUFFERING PACKET')
            stage.delayedPackets.append([message_num, payload])
        else:
            if not stage.finishedSending:
                stage.delayedPackets.append([message_num, payload])
            else:
                self.sshParse.parse_packet("[SERVER]", message_num, payload)

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

    def dataReceived(self, data):
        """
        First, check for the version string (SSH-2.0-*).  After that has been
        received, this method adds data to the buffer, and pulls out any
        packets.

        @type data: C{str}
        """
        self.buf += data

        if not self.gotVersion:
            if self.buf.find('\n', self.buf.find('SSH-')) == -1:
                return
            lines = self.buf.split('\n')
            for p in lines:
                if p.startswith('SSH-'):
                    self.gotVersion = True
                    self.otherVersionString = p.strip()
                    remote_version = p.split('-')[1]

                    if remote_version not in self.supportedVersions:
                        self._unsupportedVersionReceived(remote_version)
                        return
                    i = lines.index(p)
                    self.buf = '\n'.join(lines[i + 1:])
                    self.sendKexInit()
        packet = self.getPacket()
        while packet:
            message_num = ord(packet[0])
            self.dispatchMessage(message_num, packet[1:])
            packet = self.getPacket()

    def sendDisconnect(self, reason, desc):
        """
        http://kbyte.snowpenguin.org/portal/2013/04/30/kippo-protocol-mismatch-workaround/
        Workaround for the "bad packet length" error message.

        @param reason: the reason for the disconnect.  Should be one of the
                       DISCONNECT_* values.
        @type reason: C{int}
        @param desc: a description of the reason for the disconnection.
        @type desc: C{str}
        """
        if 'bad packet length' not in desc:
            # With python >= 3 we can use super?
            transport.SSHServerTransport.sendDisconnect(self, reason, desc)
        else:
            self.transport.write('Protocol mismatch.\n')
            log.msg(log.LRED, '[SERVER]', 'Disconnecting with error, code %s\nreason: %s' % (reason, desc))
            self.transport.loseConnection()


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
