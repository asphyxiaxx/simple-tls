# Copyright (c) 2026 The simple-tls Contributors

# Permission is hereby granted, free of charge, to any person obtaining a copy of
# this software and associated documentation files (the “Software”), to deal in
# the Software without restriction, including without limitation the rights to
# use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of
# the Software, and to permit persons to whom the Software is furnished to do so,
# subject to the following conditions:

# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.

# THE SOFTWARE IS PROVIDED “AS IS”, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS
# FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR
# COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER
# IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
# CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

from __future__ import annotations

import enum


class TLSVerifyMode(int, enum.Enum):
    CERT_NONE = 0
    CERT_OPTIONAL = 1
    CERT_REQUIRED = 2


class TLSSessionType(int, enum.Enum):
    not_resumable = enum.auto()
    session_id = enum.auto()
    session_ticket = enum.auto()
    pre_shared_key = enum.auto()


class Direction(int, enum.Enum):
    DECRYPT = 0
    ENCRYPT = 1


class Epoch(int, enum.Enum):
    INITIAL = 0
    ZERO_RTT = 1
    HANDSHAKE = 2
    APPLICATION_DATA = 3


class Status(int, enum.Enum):
    OK = enum.auto()
    EARLY_RETURN = enum.auto()
    READ_CHANGE_CIPHER_SPEC = enum.auto()
    READ_END_OF_EARLY_DATA = enum.auto()
    READ_MESSAGE = enum.auto()
    PACK_FLIGHT = enum.auto()
    FLUSH_MESSAGE = enum.auto()


class Shutdown(int, enum.Enum):
    NONE = enum.auto()
    CLOSE_NOTIFY = enum.auto()
    ERROR = enum.auto()


class ClientHelloType(int, enum.Enum):
    UNENCRYPTED = enum.auto()
    INNER = enum.auto()
    OUTER = enum.auto()


class ECHStatus(int, enum.Enum):
    NONE = 0
    ACCEPTED = 1
    REJECTED = 2


class ClientState(int, enum.Enum):
    START_CONNECT = enum.auto()
    ENTER_EARLY_DATA = enum.auto()
    READ_SERVER_HELLO = enum.auto()
    READ_SERVER_CERTIFICATE = enum.auto()
    READ_CERTIFICATE_STATUS = enum.auto()
    VERIFY_SERVER_CERTIFICATE = enum.auto()
    READ_SERVER_KEY_EXCHANGE = enum.auto()
    READ_CERTIFICATE_REQUEST = enum.auto()
    READ_SERVER_HELLO_DONE = enum.auto()
    SEND_CLIENT_CERTIFICATE = enum.auto()
    SEND_CLIENT_KEY_EXCHANGE = enum.auto()
    SEND_CLIENT_CERTIFICATE_VERIFY = enum.auto()
    SEND_CLIENT_FINISHED = enum.auto()
    FINISH_FLIGHT = enum.auto()
    READ_SESSION_TICKET = enum.auto()
    PROCESS_CHANGE_CIPHER_SPEC = enum.auto()
    READ_SERVER_FINISHED = enum.auto()
    # TLSv1.3
    READ_HRR_TLS13 = enum.auto()
    SEND_SECOND_CLIENT_HELLO_TLS13 = enum.auto()
    READ_SERVER_HELLO_TLS13 = enum.auto()
    READ_ENCRYPTED_EXTENSIONS_TLS13 = enum.auto()
    READ_CERTIFICATE_REQUEST_TLS13 = enum.auto()
    READ_SERVER_CERTIFICATE_TLS13 = enum.auto()
    READ_SERVER_CERTIFICATE_VERIFY_TLS13 = enum.auto()
    READ_SERVER_FINISHED_TLS13 = enum.auto()
    SEND_END_OF_EARLY_DATA_TLS13 = enum.auto()
    SEND_CLIENT_ENCRYPTED_EXTENSIONS_TLS13 = enum.auto()
    SEND_CLIENT_CERTIFICATE_TLS13 = enum.auto()
    SEND_CLIENT_FINISHED_TLS13 = enum.auto()
    COMPLETE_SECOND_FLIGHT_TLS13 = enum.auto()
    # Finish handshake
    FINISH_CLIENT_HANDSHAKE = enum.auto()
    DONE = enum.auto()
    # Post handshake
    READ_POST_HANDSHAKE = enum.auto()
    PROCESS_UPDATE_TRAFFIC = enum.auto()
    COMPLETE_UPDATE_TRAFFIC = enum.auto()


class ServerState(int, enum.Enum):
    START_ACCEPT = enum.auto()
    READ_CLIENT_HELLO = enum.auto()
    SELECT_PARAMETERS = enum.auto()
    SEND_SERVER_HELLO = enum.auto()
    SEND_SERVER_CERTIFICATE = enum.auto()
    SEND_SERVER_KEY_EXCHANGE = enum.auto()
    SEND_SERVER_HELLO_DONE = enum.auto()
    READ_CLIENT_CERTIFICATE = enum.auto()
    VERIFY_CLIENT_CERTIFICATE = enum.auto()
    READ_CLIENT_KEY_EXCHANGE = enum.auto()
    READ_CLIENT_CERTIFICATE_VERIFY = enum.auto()
    READ_CHANGE_CIPHER_SPEC = enum.auto()
    PROCESS_CHANGE_CIPHER_SPEC = enum.auto()
    READ_NEXT_PROTO = enum.auto()
    READ_CLIENT_FINISHED = enum.auto()
    SEND_SESSION_TICKET = enum.auto()
    SEND_SERVER_FINISHED = enum.auto()
    # TLSv1.3
    SELECT_PARAMETERS_TLS13 = enum.auto()
    SEND_HELLO_RETRY_REQUEST_TLS13 = enum.auto()
    READ_SECOND_CLIENT_HELLO_TLS13 = enum.auto()
    SEND_SERVER_HELLO_TLS13 = enum.auto()
    SEND_ENCRYPTED_EXTENSIONS_TLS13 = enum.auto()
    SEND_SERVER_FINISHED_TLS13 = enum.auto()
    READ_SECOND_CLIENT_FLIGHT_TLS13 = enum.auto()
    PROCESS_END_OF_EARLY_DATA_TLS13 = enum.auto()
    READ_CLIENT_ENCRYPTED_EXTENSIONS_TLS13 = enum.auto()
    READ_CLIENT_CERTIFICATE_TLS13 = enum.auto()
    READ_CLIENT_CERTIFICATE_VERIFY_TLS13 = enum.auto()
    READ_CLIENT_FINISHED_TLS13 = enum.auto()
    SEND_NEWSESSION_TICKET_TLS13 = enum.auto()
    # Finish handshake
    FINISHED_SERVER_HANDSHAKE = enum.auto()
    DONE = enum.auto()
    # Post handshake
    READ_POST_HANDSHAKE = enum.auto()
    PROCESS_UPDATE_TRAFFIC = enum.auto()
    COMPLETE_UPDATE_TRAFFIC = enum.auto()
