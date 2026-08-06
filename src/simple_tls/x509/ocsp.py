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

import datetime
import enum
import typing
from typing import TypeAlias

from ..io import asn1
from ..io.oid import AlgorithmIdentifier, ObjectIdentifier
from .base import Certificate
from .extensions import Extensions
from .name import _GeneralName


@asn1.sequence(frozen=True)
class CertID:
    # CertID ::= SEQUENCE {
    #     hashAlgorithm       AlgorithmIdentifier,
    #     issuerNameHash      OCTET STRING,  -- Hash of issuer's DN
    #     issuerKeyHash       OCTET STRING,  -- Hash of issuer's public key
    #     serialNumber        CertificateSerialNumber
    # }
    hash_algorithm: AlgorithmIdentifier
    issuer_name_hash: bytes
    issuer_key_hash: bytes
    serial_number: int


@asn1.sequence(frozen=True)
class Signature:
    signature_algorithm: AlgorithmIdentifier
    signature: asn1.BitString
    certs: asn1.Annotated[list[Certificate], asn1.Explicit(0)] | None


@asn1.sequence(frozen=True)
class Request:
    # Request ::= SEQUENCE {
    #     reqCert                     CertID,
    #     singleRequestExtensions     [0] EXPLICIT Extensions OPTIONAL
    # }
    request_cert: CertID
    single_request_extensions: (
        asn1.Annotated[Extensions, asn1.Explicit(0)] | None
    )


@asn1.sequence(frozen=True)
class TBSRequest:
    # TBSRequest ::= SEQUENCE {
    #     version             [0] EXPLICIT Version DEFAULT v1,
    #     requestorName       [1] EXPLICIT GeneralName OPTIONAL,
    #     requestList             SEQUENCE OF Request,
    #     requestExtensions   [2] EXPLICIT Extensions OPTIONAL
    # }
    version: asn1.Annotated[int, asn1.Explicit(0)] = 0
    requestor_name: asn1.Annotated[_GeneralName, asn1.Explicit(1)] | None
    request_list: list[Request]
    request_extensions: asn1.Annotated[Extensions, asn1.Explicit(2)] | None


@asn1.sequence(frozen=True)
class OCSPRequest:
    # OCSPRequest ::= SEQUENCE {
    #     tbsRequest                  TBSRequest,
    #     optionalSignature   [0]     EXPLICIT Signature OPTIONAL
    # }
    tbs_request: TBSRequest
    optional_signature: asn1.Annotated[Signature, asn1.Explicit(0)] | None


@asn1.mapped(base_type=asn1.Enumerated)
class CRLReason(enum.IntEnum):
    UNSPECIFIED = 0
    KEY_COMPROMISE = 1
    CA_COMPROMISE = 2
    AFFILIATION_CHANED = 3
    SUPERSEDED = 4
    CESSATION_OF_OPERATION = 5
    CERTIFICATE_HOLD = 6
    REMOVE_FROM_CRL = 8
    PRIVILEGE_WITHDRAWN = 9
    AA_COMPROMISE = 10

    def to_encoder(self) -> int:
        return self

    @classmethod
    def from_decoder(cls, value: int) -> CRLReason:
        return CRLReason(value)


@asn1.sequence(frozen=True)
class RevokedInfo:
    # RevokedInfo ::= SEQUENCE {
    #    revocationTime              GeneralizedTime,
    #    revocationReason    [0]     EXPLICIT CRLReason OPTIONAL
    # }
    revocation_time: asn1.GeneralizedTime
    revocation_reason: asn1.Annotated[CRLReason, asn1.Explicit(0)] | None


CertStatus: TypeAlias = typing.Union[
    asn1.Annotated[
        asn1.Variant[typing.Literal["good"], asn1.Null],
        asn1.Implicit(0),
    ],
    asn1.Annotated[
        asn1.Variant[typing.Literal["revoked"], RevokedInfo],
        asn1.Implicit(1),
    ],
    asn1.Annotated[
        asn1.Variant[typing.Literal["unknown"], asn1.Null],
        asn1.Implicit(2),
    ],
]


@asn1.sequence(frozen=True)
class SingleResponse:
    # CertStatus ::= CHOICE {
    #     good        [0] IMPLICIT NULL,
    #     revoked     [1] IMPLICIT RevokedInfo,
    #     unknown     [2] IMPLICIT NULL
    # }

    # SingleResponse ::= SEQUENCE {
    #    certID               CertID,
    #    certStatus           CertStatus,
    #    thisUpdate           GeneralizedTime,
    #    nextUpdate           [0] EXPLICIT GeneralizedTime OPTIONAL,
    #    singleExtensions     [1] EXPLICIT Extensions OPTIONAL
    # }
    cert_id: CertID
    cert_status: CertStatus
    this_update: asn1.GeneralizedTime
    next_update: asn1.Annotated[asn1.GeneralizedTime, asn1.Explicit(0)] | None
    single_extensions: asn1.Annotated[Extensions, asn1.Explicit(1)] | None

    @property
    def hash_algorithm_oid(self) -> ObjectIdentifier:
        return self.cert_id.hash_algorithm.oid

    @property
    def issuer_key_hash(self) -> bytes:
        return self.cert_id.issuer_key_hash

    @property
    def issuer_name_hash(self) -> bytes:
        return self.cert_id.issuer_name_hash

    @property
    def serial_number(self) -> int:
        return self.cert_id.serial_number

    @property
    def status(self) -> str:
        return self.cert_status.name

    @property
    def revocation_time(self) -> datetime.datetime | None:
        if isinstance(self.cert_status.value, RevokedInfo):
            return self.cert_status.value.revocation_time
        return None

    @property
    def revocation_reason(self) -> CRLReason | None:
        if isinstance(self.cert_status.value, RevokedInfo):
            return self.cert_status.value.revocation_reason
        return None


@asn1.sequence(frozen=True)
class ResponseData:
    # ResponseData ::= SEQUENCE {
    #    version              [0] EXPLICIT Version DEFAULT v1,
    #    responderID          ResponderID,
    #    producedAt           GeneralizedTime,
    #    responses            SEQUENCE OF SingleResponse,
    #    responseExtensions   [1] EXPLICIT Extensions OPTIONAL
    # }
    version: asn1.Annotated[int, asn1.Explicit(0)] = 0
    responser_id: asn1.Annotated[bytes, asn1.Explicit(2)]
    produced_at: asn1.GeneralizedTime
    responses: asn1.SequenceOf[SingleResponse]
    response_extensions: asn1.Annotated[Extensions, asn1.Explicit(1)] | None


@asn1.sequence(frozen=True)
class BasicOCSPResponse:
    # BasicOCSPResponse ::= SEQUENCE {
    #    tbsResponseData      ResponseData,
    #    signatureAlgorithm   AlgorithmIdentifier,
    #    signature            BIT STRING,
    #    certs            [0] EXPLICIT SEQUENCE OF Certificate OPTIONAL
    # }
    tbs_response_data: ResponseData
    signature_algorithm: AlgorithmIdentifier
    signature_value: asn1.BitString
    certs: asn1.Annotated[list[Certificate], asn1.Explicit(0)] | None

    @property
    def signature(self) -> bytes:
        return self.signature_value.data


@asn1.sequence(frozen=True)
class ResponseBytes:
    # ResponseBytes ::= SEQUENCE {
    #    responseType   OBJECT IDENTIFIER,
    #    response       OCTET STRING
    # }
    response_type: ObjectIdentifier
    response: asn1.Annotated[
        BasicOCSPResponse,
        asn1.OpenType(
            base_type=asn1.OctetString,
            defined_by="response_type",
            typemap={
                "1.3.6.1.5.5.7.48.1.1": BasicOCSPResponse,
            },
        ),
    ]


@asn1.mapped(base_type=asn1.Enumerated)
class ResponseStatus(enum.IntEnum):
    SUCCESSFUL = 0
    MALFORMED_REQUEST = 1
    INTERNAL_ERROR = 2
    TRY_LATER = 3
    SIGNATURE_REQUIRED = 5
    UNAUTHORIZED = 6

    def to_encoder(self) -> int:
        return self

    @classmethod
    def from_decoder(cls, value: int) -> ResponseStatus:
        return ResponseStatus(value)


@asn1.sequence(frozen=True)
class OCSPResponse:
    # OCSPResponse ::= SEQUENCE {
    #     responseStatus         OCSPResponseStatus,
    #     responseBytes          [0] EXPLICIT ResponseBytes OPTIONAL
    # }
    response_status: ResponseStatus
    response_bytes: asn1.Annotated[ResponseBytes, asn1.Explicit(0)] | None


def load_der_ocsp_response(data: bytes) -> OCSPResponse:
    return asn1.decode(data, OCSPResponse, OCSPResponse.__name__)[0]


def load_der_ocsp_request(data: bytes) -> OCSPRequest:
    return asn1.decode(data, OCSPRequest, OCSPRequest.__name__)[0]
