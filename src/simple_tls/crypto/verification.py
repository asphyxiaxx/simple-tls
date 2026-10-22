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

import os
from collections import deque
from collections.abc import Callable, Iterable, Sequence
from datetime import datetime, timedelta, timezone
from os import PathLike
from pathlib import Path
from typing import TypeAlias, Union

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.x509.oid import ExtensionOID

StrOrBytesPath: TypeAlias = str | bytes | PathLike[str] | PathLike[bytes]
MaybeExtensionCallback: TypeAlias = Callable[
    ["Verifier", x509.Certificate, x509.Extension | None], None
]
PresentExtensionCallback: TypeAlias = Callable[
    ["Verifier", x509.Certificate, x509.Extension], None
]


class VerificationError(Exception):
    """
    Exception raised when error occurred while verify certificate.
    """

    def __init__(
        self, certificate: x509.Certificate, message: str | None = None
    ) -> None:
        if message is not None:
            super().__init__(message)
        else:
            super().__init__()
        self.certificate = certificate


class SignatureVerificationError(VerificationError): ...


class PolicyViolationError(VerificationError): ...


class CertificateNotYetValid(VerificationError): ...


class CertificateExpired(VerificationError): ...


class UntrustedRoot(VerificationError): ...


class Store:
    def __init__(self) -> None:
        # trust map: subject -> list of certs with that subject
        self._trust_map: dict[x509.Name, list[x509.Certificate]] = {}

    def get_certificates(self) -> list[x509.Certificate]:
        return [cert for certs in self._trust_map.values() for cert in certs]

    def add_certificate(self, certificate: x509.Certificate) -> None:
        self._trust_map.setdefault(certificate.subject, []).append(certificate)

    def load_locations(
        self,
        cafile: StrOrBytesPath | None = None,
        capath: StrOrBytesPath | None = None,
    ) -> None:
        certs: list[x509.Certificate] = []

        if cafile:
            with open(cafile, "rb") as fp:
                pem_data = fp.read()
            certs.extend(x509.load_pem_x509_certificates(pem_data))

        if capath:
            path = Path(_ensure_str_path(capath))
            if path.is_dir():
                for file_path in path.iterdir():
                    if not file_path.is_file():
                        continue
                    try:
                        with open(file_path, "rb") as fp:
                            pem_data = fp.read()
                        certs.extend(x509.load_pem_x509_certificates(pem_data))
                    except Exception:
                        pass

        for cert in certs:
            self._trust_map.setdefault(cert.subject, []).append(cert)

    def get_trust_map(self) -> dict[x509.Name, list[x509.Certificate]]:
        return self._trust_map.copy()


class ExtensionPolicy:
    def __init__(
        self,
        *,
        _may_be_present: Union[
            dict[x509.ObjectIdentifier, MaybeExtensionCallback | None], None
        ] = None,
        _require_present: Union[
            dict[x509.ObjectIdentifier, PresentExtensionCallback | None], None
        ] = None,
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
        extension_oid: x509.ObjectIdentifier,
        validator: MaybeExtensionCallback | None = None,
    ) -> ExtensionPolicy:
        if not isinstance(extension_oid, x509.ObjectIdentifier):
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
        extension_oid: x509.ObjectIdentifier,
        validator: PresentExtensionCallback | None = None,
    ) -> ExtensionPolicy:
        if not isinstance(extension_oid, x509.ObjectIdentifier):
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

    def verify(
        self, verifier: Verifier, certificate: x509.Certificate
    ) -> None:
        exts = certificate.extensions

        for oid, valitator in self._require_present.items():
            try:
                r_ext = exts.get_extension_for_oid(oid)
            except x509.ExtensionNotFound:
                err_str = (
                    f"Extension '{oid}' required not found in {certificate}"
                )
                raise PolicyViolationError(certificate, err_str) from None

            if valitator is not None:
                valitator(verifier, certificate, r_ext)

        for oid, valitator in self._may_be_present.items():
            try:
                m_ext = exts.get_extension_for_oid(oid)
            except x509.ExtensionNotFound:
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
        if max_chain_depth <= 0:
            raise ValueError("max_chain_depth must be larger then 0")
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
        self, leaf: x509.Certificate, intermediates: Iterable[x509.Certificate]
    ) -> list[x509.Certificate]:
        chains = self._build_candidate_chains(leaf, intermediates)
        if not chains:
            raise UntrustedRoot(leaf)

        chain = chains[0]
        self._verify_chain(chain)
        return chain

    # Internal

    def _build_candidate_chains(
        self, leaf: x509.Certificate, intermediates: Iterable[x509.Certificate]
    ) -> list[list[x509.Certificate]]:
        """
        Build possible chains starting at leaf. Each chain is
        [leaf, iss1, iss2, ..., trust_anchor_candidate]
        Do BFS to find shortest chains first, and use basic
        filters (subject/issuer, AKI/SKI).
        """
        # include store certs as possible issuers too
        roots_by_subject = self.store.get_trust_map()
        candidates_by_subject = roots_by_subject.copy()
        for c in intermediates:
            candidates_by_subject.setdefault(c.subject, []).append(c)

        chains: list[list[x509.Certificate]] = []
        q: deque[list[x509.Certificate]] = deque()
        q.append([leaf])

        # avoid repeating same (subject, issuer, serial) loops
        seen_sigpairs: set[tuple[x509.Name, x509.Name, int]] = set()

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
                store_certs = roots_by_subject.get(issuer.subject, [])
                is_trusted_anchor = any(issuer is sc for sc in store_certs)

                if is_trusted_anchor:
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

    def _verify_chain(self, chain: Sequence[x509.Certificate]) -> None:
        """
        Verify chain top-down: for i in range(len(chain)-1):
            verify chain[i] signed by chain[i+1] (parent)

        The last cert in chain should be a trusted anchor from policy.store

        :raises VerificationError: on verification failure.
        """
        if not chain:
            raise ValueError("chain cannot be empty")
        if len(chain) > self.max_chain_depth:
            raise PolicyViolationError(
                chain[0], "chain length exceeds max depth"
            )

        now = datetime.now(timezone.utc)
        skew = 300

        # ca_count_below: number of CA certs below current issuer per RFC
        # pathLen semantics
        ca_count_below = 0

        # iterate from leaf up to (parent = next)
        child_bc = None
        for index in range(len(chain) - 1):
            child = chain[index]
            issuer = chain[index + 1]

            # validity
            self._verify_validity_now(index, child, now, skew)

            # signature
            self._verify_signature(index, child, issuer)

            # Basic constraint
            try:
                bc = issuer.extensions.get_extension_for_class(
                    x509.BasicConstraints
                ).value
            except x509.ExtensionNotFound:
                err_str = (
                    "issuer certificate missing basic constraint extension"
                )
                raise PolicyViolationError(issuer, err_str) from None

            if bc.path_length is not None and ca_count_below > bc.path_length:
                err_str = (
                    f"issuer certificate violated path len constraint "
                    f"[{ca_count_below} > {bc.path_length}]"
                )
                raise PolicyViolationError(issuer, err_str)

            if not bc.ca:
                err_str = "issuer certificate is not CA certificate"
                raise PolicyViolationError(issuer, err_str)

            if index == 0:
                try:
                    child_bc = child.extensions.get_extension_for_class(
                        x509.BasicConstraints
                    ).value
                except x509.ExtensionNotFound:
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
        index: int, child: x509.Certificate, issuer: x509.Certificate
    ) -> None:
        try:
            child.verify_directly_issued_by(issuer)
        except InvalidSignature:
            raise SignatureVerificationError(child) from None

    @staticmethod
    def _verify_validity_now(
        index: int, child: x509.Certificate, now: datetime, skew: int = 300
    ) -> None:
        """
        Return VerificationError if cert not valid wrt now +/- skew seconds.
        """
        not_before = child.not_valid_before_utc
        not_after = child.not_valid_after_utc
        delta = timedelta(seconds=skew)

        if now + delta < not_before:
            raise CertificateNotYetValid(child)
        if now - delta > not_after:
            raise CertificateExpired(child)

    @staticmethod
    def _aki_ski_compatible(
        issuer: x509.Certificate, cert: x509.Certificate
    ) -> bool:
        # If AKI present in cert and SKI present in issuer, match them.
        try:
            aki = cert.extensions.get_extension_for_class(
                x509.AuthorityKeyIdentifier
            ).value
        except x509.ExtensionNotFound:
            aki = None

        try:
            ski = issuer.extensions.get_extension_for_class(
                x509.SubjectKeyIdentifier
            ).value
        except x509.ExtensionNotFound:
            ski = None

        if aki is not None and ski is not None:
            return aki.key_identifier == ski.key_identifier
        else:
            return True  # if either missing, don't exclude

    @staticmethod
    def _is_self_issued(certificate: x509.Certificate) -> bool:
        """
        Check if the certificate is self-issued (subject == issuer).
        RFC 5280 section 4.2.1.9
        """
        return certificate.subject == certificate.issuer


# Default extension policy implementations


def verify_ca_key_usage(
    verifier: Verifier,
    certificate: x509.Certificate,
    extension: x509.Extension[x509.KeyUsage] | None,
) -> None:
    if extension is None:
        return

    key_usage = extension.value
    if not key_usage.key_cert_sign:
        err_str = (
            "issuer certificate not allowed to sign certificates"
            " as it's key usage extension missing key_cert_sign"
        )
        raise PolicyViolationError(certificate, err_str)


# Internal


def _ensure_str_path(path_input: StrOrBytesPath) -> str:
    if isinstance(path_input, bytes):
        return path_input.decode("utf-8")

    fspath = os.fspath(path_input)
    if isinstance(fspath, bytes):
        return fspath.decode("utf-8")
    return fspath
