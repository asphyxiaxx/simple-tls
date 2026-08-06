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

import typing
from collections import deque
from datetime import datetime, timedelta

from cryptography.exceptions import InvalidSignature

from ..io.oid import ExtensionOID, ObjectIdentifier
from ..utils.misc import utcnow
from .base import Certificate
from .extensions import (
    AuthorityKeyIdentifier,
    BasicConstraints,
    Extension,
    ExtensionNotFound,
    ExtensionType,
    KeyUsage,
    SubjectKeyIdentifier,
)
from .name import Name

_T = typing.TypeVar("_T", contravariant=True, bound="ExtensionType")
_MaybeExtCallback = typing.Callable[
    ["Verifier", Certificate, Extension | None], None
]
_PresentExtCallback = typing.Callable[
    ["Verifier", Certificate, Extension], None
]


class VerificationError(Exception): ...


class SignatureVerificationError(VerificationError): ...


class PolicyViolationError(VerificationError): ...


class CertificateNotYetValid(VerificationError): ...


class CertificateExpired(VerificationError): ...


class UntrustedRoot(VerificationError): ...


class Store:
    def __init__(self, certs: list[Certificate] | None = None):
        if certs is None:
            certs = []

        self._certs = certs
        # trust map: subject -> list of certs with that subject
        self._trust_map: dict[Name, list[Certificate]] = {}
        for c in self._certs:
            self._trust_map.setdefault(c.subject, []).append(c)

    def __iter__(self) -> typing.Iterator[Certificate]:
        return iter(self._certs)

    def __len__(self) -> int:
        return len(self._certs)

    @typing.overload
    def get(self, key: Name, default: _T = ...) -> list[Certificate] | _T: ...

    @typing.overload
    def get(
        self, key: Name, default: None = ...
    ) -> list[Certificate] | None: ...

    def get(
        self, key: Name, default: _T | None = None
    ) -> list[Certificate] | _T | None:
        return self._trust_map.get(key, default)

    def append(self, cert: Certificate) -> None:
        self._certs.append(cert)
        self._trust_map.setdefault(cert.subject, []).append(cert)

    def extend(self, certs: list[Certificate]) -> None:
        self._certs.extend(certs)
        for c in certs:
            self._trust_map.setdefault(c.subject, []).append(c)

    def get_trust_map(self) -> dict[Name, list[Certificate]]:
        return self._trust_map.copy()


class ExtensionPolicy:
    def __init__(
        self,
        *,
        _may_be_present: dict[ObjectIdentifier, _MaybeExtCallback | None]
        | None = None,
        _require_present: dict[ObjectIdentifier, _PresentExtCallback | None]
        | None = None,
    ) -> None:
        self._may_be_present = (
            _may_be_present.copy() if _may_be_present else {}
        )
        self._require_present = (
            _require_present.copy() if _require_present else {}
        )

    @classmethod
    def defaults_ca(cls) -> ExtensionPolicy:
        return ExtensionPolicy(
            _may_be_present={
                ExtensionOID.KEY_USAGE: verify_ca_key_usage,
            }
        )

    @classmethod
    def defaults_ee(cls) -> ExtensionPolicy:
        return ExtensionPolicy()

    def may_be_present(
        self,
        extension_oid: ObjectIdentifier,
        validator: _MaybeExtCallback | None = None,
    ) -> ExtensionPolicy:
        if not isinstance(extension_oid, ObjectIdentifier):
            raise TypeError("extension_oid must be ObjectIdentifier object")
        if validator is not None and not callable(validator):
            raise TypeError("validator must be callable")

        may_be_present = self._may_be_present.copy()
        may_be_present[extension_oid] = validator

        require_present = self._require_present.copy()
        require_present.pop(extension_oid, None)

        return ExtensionPolicy(
            _may_be_present=may_be_present,
            _require_present=require_present,
        )

    def require_present(
        self,
        extension_oid: ObjectIdentifier,
        validator: _PresentExtCallback | None = None,
    ) -> ExtensionPolicy:
        if not isinstance(extension_oid, ObjectIdentifier):
            raise TypeError("extension_oid must be ObjectIdentifier object")
        if validator is not None and not callable(validator):
            raise TypeError("validator must be callable")

        require_present = self._require_present.copy()
        require_present[extension_oid] = validator

        may_be_present = self._may_be_present.copy()
        may_be_present.pop(extension_oid, None)

        return ExtensionPolicy(
            _may_be_present=may_be_present,
            _require_present=require_present,
        )

    def verify(self, verifier: Verifier, certificate: Certificate) -> None:
        exts = certificate.extensions

        for oid, valitator in self._require_present.items():
            try:
                r_ext = exts.get_extension_for_oid(oid)
            except ExtensionNotFound:
                raise PolicyViolationError(
                    f"Extension '{oid}' required not found in {certificate}"
                ) from None

            if valitator is not None:
                valitator(verifier, certificate, r_ext)

        for oid, valitator in self._may_be_present.items():
            try:
                m_ext = exts.get_extension_for_oid(oid)
            except ExtensionNotFound:
                m_ext = None

            if valitator is not None:
                valitator(verifier, certificate, m_ext)


class Verifier:
    def __init__(
        self,
        store: Store,
        max_chain_depth: int = 8,
        allow_partial_chain: bool = False,
        ee_policy: ExtensionPolicy | None = None,
        ca_policy: ExtensionPolicy | None = None,
    ) -> None:
        if ee_policy is None:
            ee_policy = ExtensionPolicy.defaults_ee()
        if ca_policy is None:
            ca_policy = ExtensionPolicy.defaults_ee()

        self._store = store
        self._allow_partial_chain = allow_partial_chain
        self._max_chain_depth = max_chain_depth
        self._ee_policy = ee_policy
        self._ca_policy = ca_policy

    @property
    def max_chain_depth(self) -> int:
        return self._max_chain_depth

    @property
    def store(self) -> Store:
        return self._store

    @property
    def allow_partial_chain(self) -> bool:
        return self._allow_partial_chain

    def verify(
        self, leaf: Certificate, intermediates: typing.Sequence[Certificate]
    ) -> tuple[Certificate, ...]:
        chains = self._build_candidate_chains(leaf, intermediates)
        if not chains:
            raise UntrustedRoot("No trusted root found")

        chain = chains[0]
        self._verify_chain(chain)
        return tuple(chain)

    # Internal

    def _build_candidate_chains(
        self,
        leaf: Certificate,
        intermediates: typing.Sequence[Certificate],
    ) -> list[list[Certificate]]:
        """
        Build possible chains starting at leaf. Each chain is
        [leaf, iss1, iss2, ..., trust_anchor_candidate]
        Do BFS to find shortest chains first, and use basic
        filters (subject/issuer, AKI/SKI).
        """
        # include store certs as possible issuers too
        candidates_by_subject = self.store.get_trust_map()
        for c in intermediates:
            candidates_by_subject.setdefault(c.subject, []).append(c)

        chains: list[list[Certificate]] = []
        q: deque[list[Certificate]] = deque()
        q.append([leaf])

        # avoid repeating same (subject, issuer, serial) loops
        seen_sigpairs: set[tuple[Name, Name, int]] = set()

        while q:
            chain = q.popleft()
            if len(chain) > self.max_chain_depth:
                continue

            tip = chain[-1]
            # if tip issuer equals some subject in the store AND we accept
            # partial or it is self-signed root:
            possible_issuers = candidates_by_subject.get(tip.issuer, [])

            for issuer in possible_issuers:
                # avoid immediate loop (same cert)
                if issuer is tip:
                    continue

                # optional AKI/SKI filter
                if not self._aki_ski_compatible(issuer, tip):
                    continue

                # avoid cycles via (leaf serials chain)
                sigid = (tip.subject, issuer.subject, issuer.serial_number)
                if sigid in seen_sigpairs:
                    continue
                seen_sigpairs.add(sigid)

                new_chain = [*chain, issuer]

                # If issuer is in store and acceptable as trust anchor,
                # record candidate chain
                store_certs = self.store.get(issuer.subject)
                if store_certs:
                    if self._is_self_issued(issuer):
                        # assert issuer in store_certs
                        chains.append(new_chain)
                    elif self.allow_partial_chain:
                        # If partial chains are ok we accept this as candidate
                        # anchor
                        chains.append(new_chain)

                # continue BFS
                q.append(new_chain)

        # If allow partial and no store anchors found,
        # still add chains that end in an intermediate
        # (if store contains that intermediate by subject)
        return chains

    def _verify_chain(self, chain: typing.Sequence[Certificate]) -> None:
        """
        Verify chain top-down: for i in range(len(chain)-1):
            verify chain[i] signed by chain[i+1] (parent)

        The last cert in chain should be a trusted anchor from policy.store

        :raises VerificationError: on verification failure.
        """
        if not chain:
            raise ValueError("chain cannot be empty")

        # check length
        if len(chain) > self.max_chain_depth:
            raise PolicyViolationError("chain length exceeds max depth")

        # ca_count_below: number of CA certs below current issuer per RFC
        # pathLen semantics
        ca_count_below = 0

        now = utcnow()
        skew = 300

        # iterate from leaf up to (parent = next)
        child_bc = None
        for i in range(len(chain) - 1):
            child = chain[i]
            issuer = chain[i + 1]

            # validity
            self._verify_validity_now(i, child, now, skew)

            # signature
            self._verify_signature(i, child, issuer)

            # Basic constraint
            try:
                bc = issuer.extensions.get_extension_for_class(
                    BasicConstraints
                ).value
            except ExtensionNotFound:
                raise PolicyViolationError(
                    f"{child} at index '{i}' has no basic constraint extension"
                    f" which is required for CA certificate"
                ) from None

            if bc.path_length is not None and ca_count_below > bc.path_length:
                raise PolicyViolationError(
                    f"{child} at index '{i}' violated path len constraint "
                    f"[{ca_count_below} > {bc.path_length}]"
                )

            if not bc.ca:
                raise PolicyViolationError(
                    f"{child} at index '{i}' is not a CA certificate"
                )

            if i == 0:
                try:
                    child_bc = child.extensions.get_extension_for_class(
                        BasicConstraints
                    ).value
                except ExtensionNotFound:
                    pass

            # increment ca_count_below if child is CA and not self-issued
            if child_bc is not None:
                if child_bc.ca and not self._is_self_issued(child):
                    ca_count_below += 1

            child_bc = bc

            # run ca extension policies for 'issuer'
            self._ca_policy.verify(self, issuer)

        # leaf-only policies (run once for chain[0])
        self._ee_policy.verify(self, chain[0])

    @staticmethod
    def _verify_signature(
        index: int,
        child: Certificate,
        issuer: Certificate,
    ) -> None:
        try:
            child.verify_directly_issued_by(issuer)
        except (TypeError, ValueError, InvalidSignature) as exc:
            err_str = (
                f"{child} at index '{index}' signature verification failed"
            )
            exc_str = str(exc)
            if exc_str:
                err_str += f" [{exc_str}]"
            raise SignatureVerificationError(err_str) from exc

    @staticmethod
    def _verify_validity_now(
        index: int, child: Certificate, now: datetime, skew: int = 300
    ) -> None:
        """
        Return VerificationError if cert not valid wrt now +/- skew seconds.
        """
        not_before = child.not_valid_before_utc
        not_after = child.not_valid_after_utc
        delta = timedelta(seconds=skew)

        if now + delta < not_before:
            raise CertificateNotYetValid(
                f"{child} at index '{index}' not valid until "
                f"{not_before.isoformat()}"
            )
        if now - delta > not_after:
            raise CertificateExpired(
                f"{child} at index '{index}' expired at "
                f"{not_after.isoformat()}"
            )

    @staticmethod
    def _is_self_issued(cert: Certificate) -> bool:
        """
        Check if the certificate is self-issued (subject == issuer).
        RFC 5280 section 4.2.1.9
        """
        return cert.subject == cert.issuer

    @staticmethod
    def _aki_ski_compatible(issuer: Certificate, cert: Certificate) -> bool:
        # If AKI present in cert and SKI present in issuer, match them.
        try:
            aki = cert.extensions.get_extension_for_class(
                AuthorityKeyIdentifier
            ).value
        except ExtensionNotFound:
            aki = None

        try:
            ski = issuer.extensions.get_extension_for_class(
                SubjectKeyIdentifier
            ).value
        except ExtensionNotFound:
            ski = None

        if aki is not None and ski is not None:
            return aki.key_identifier == ski.key_identifier
        else:
            return True  # if either missing, don't exclude


# Default extension policy implementations


def verify_ca_key_usage(
    verifier: Verifier,
    ca: Certificate,
    extension: Extension[KeyUsage] | None,
) -> None:
    if extension is None:
        return

    key_usage = extension.value
    if not key_usage.key_cert_sign:
        raise PolicyViolationError(
            f"issuer {ca} not allowed to sign certificates "
            f"[key usage has no key cert sign set]"
        )
