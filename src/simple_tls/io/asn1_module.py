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

from .asn1 import Any, BitString, ObjectIdentifier, sequence


@sequence(frozen=True)
class AlgorithmIdentifier:
    # ALGORITHM_IDENTIFIER ::= SEQUENCE {
    #     algorithm        OBJECT IDENTIFIER,
    #     parameters       ANY DEFINED BY algorithm OPTIONAL
    # }
    oid: ObjectIdentifier
    parameters: Any | None

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, AlgorithmIdentifier):
            return NotImplemented
        return self.oid == other.oid and self.parameters == other.parameters

    def __hash__(self) -> int:
        return hash((self.oid, self.parameters))


@sequence(frozen=True)
class SubjectPublicKeyInfo:
    # SubjectPublicKeyInfo ::= SEQUENCE {
    #     algorithm            AlgorithmIdentifier  -- SEQUENCE,
    #     subjectPublicKey     BIT STRING           -- BIT STRING,
    # }
    algorithm: AlgorithmIdentifier
    subject_public_key: BitString

    @property
    def subject_public_key_bytes(self) -> bytes:
        if self.subject_public_key.unused_bits != 0:
            raise ValueError("subject_public_key unused bits not 0")
        return self.subject_public_key.data
