# Copyright (c) 2026 The simple-tls Contributors
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

from __future__ import annotations

from typing_extensions import Buffer

def keygen(level: int, coins: Buffer, /) -> tuple[bytes, bytes]:
    """Generate a public and private keypair

    :param level: The security parameter level. Must be 512, 768, or 1024.
    :type level: int
    :param coins:
        seed entropy/randomness for key generation. Must be 64 bytes
    :type coins: bytes
    :return: public key and private key
    :rtype: tuple[bytes, bytes]
    """

def encaps(
    level: int, public_key: Buffer, coins: Buffer, /
) -> tuple[bytes, bytes]:
    """Generates cipher text and shared secret for given public key

    :param level: The security parameter level. Must be 512, 768, or 1024.
    :type level: int
    :param public_key:
        public key received
    :type public_key: bytes
    :param coins:
        seed entropy/randomness for key encapsulation. Must be 32 bytes
    :type coins: bytes
    :return: cipher text and shared secret
    :rtype: tuple[bytes, bytes]
    """

def decaps(level: int, ciphertext: Buffer, private_key: Buffer, /) -> bytes:
    """Generates shared secret from given cipher text

    :param level: The security parameter level. Must be 512, 768, or 1024.
    :type level: int
    :param ciphertext: cipher text recevied
    :type ciphertext: bytes
    :param private_key: private key recevied
    :type private_key: bytes
    :return: shared secret
    :rtype: bytes
    """
