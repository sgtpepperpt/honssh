#!/usr/bin/env python

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

import sys
import os

from twisted.internet import reactor
from twisted.conch.ssh.keys import Key
from twisted.python import log
from twisted.application import internet, service

from honssh import serverTransport


'''
Check to activate dev mode
'''
log.startLogging(sys.stdout, setStdout=0)

ssh_addr = '127.0.0.1'

'''
Log and session paths
'''
log_path = 'logs'
if not os.path.exists(log_path):
    os.makedirs(log_path)
    os.chmod(log_path, 0o755)

session_path = 'sessions'
if not os.path.exists(session_path):
    os.makedirs(session_path)
    os.chmod(session_path, 0o755)

'''
Read public and private keys
'''
with open('id_rsa') as privateBlobFile:
    privateBlob = privateBlobFile.read()
    privateKey = Key.fromString(data=privateBlob)

with open('id_rsa.pub') as publicBlobFile:
    publicBlob = publicBlobFile.read()
    publicKey = Key.fromString(data=publicBlob)

with open('id_dsa') as privateBlobFile:
    privateBlob = privateBlobFile.read()
    privateKeyDSA = Key.fromString(data=privateBlob)

with open('id_dsa.pub') as publicBlobFile:
    publicBlob = publicBlobFile.read()
    publicKeyDSA = Key.fromString(data=publicBlob)

'''
Startup server factory
'''
serverFactory = serverTransport.HonsshServerFactory()
serverFactory.privateKeys = {b'ssh-rsa': privateKey, b'ssh-dss': privateKeyDSA}
serverFactory.publicKeys = {b'ssh-rsa': publicKey, b'ssh-dss': publicKeyDSA}

'''
Start up server
'''
application = service.Application('honeypot')
service = internet.TCPServer(2222, serverFactory, interface=ssh_addr)
service.setServiceParent(application)

