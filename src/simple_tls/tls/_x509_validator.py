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

import ipaddress
import re
import typing

from .. import x509
from ._alert import AlertBadCertificate


class Validator:
    oid: typing.ClassVar[x509.ObjectIdentifier]

    def __call__(
        self,
        verifier: x509.Verifier,
        ee: x509.Certificate,
        extension: typing.Any,
    ) -> None:
        raise NotImplementedError


class SANValidator(Validator):
    oid = x509.ExtensionOID.SUBJECT_ALTERNATIVE_NAME

    def __init__(self, server_hostname: str) -> None:
        self._server_hostname = server_hostname

    def __call__(
        self,
        verifier: x509.Verifier,
        ee: x509.Certificate,
        extension: x509.Extension[x509.SubjectAlternativeName],
    ) -> None:
        server_hostname = self._server_hostname
        is_ip = False
        try:
            ip_addr = ipaddress.ip_address(server_hostname)
            is_ip = True
        except ValueError:
            ip_addr = None

        # if IP, compare iPAddress entries
        san = extension.value
        if is_ip:
            for entry in san.get_values_for_type(x509.IPAddress):
                if ip_addr == entry:
                    return
        else:
            dns_names = san.get_values_for_type(x509.DNSName)
            for dns in dns_names:
                # compare lower-case, simple wildcard handling
                if self._dnsname_match(dns, server_hostname):
                    return
            raise AlertBadCertificate(
                f"hostname '{server_hostname}' not covered by {dns_names}"
            )

    @staticmethod
    def _dnsname_match(pattern: str, hostname: str) -> bool:
        """
        Basic implementation of wildcard matching per RFC 6125 rules:
        - Only a single wildcard in the left-most label is allowed,
          e.g. *.example.com
        - Wildcard must match at least one char
          (so *.example.com matches foo.example.com but not example.com)
        """
        pattern = pattern.lower()
        hostname = hostname.lower()

        if pattern == hostname:
            return True

        if pattern.count("*") == 0:
            return False

        # simple rules: wildcard only in left-most label
        parts_pat = pattern.split(".")
        parts_host = hostname.split(".")
        if parts_pat[0] != "*" and parts_pat[0].find("*") != -1:
            # only single '*' accepted as entire label
            return False

        # only single wildcard in left-most label
        if parts_pat[0] != "*" or len(parts_pat) != len(parts_host):
            return False
        return parts_pat[1:] == parts_host[1:]

    @staticmethod
    def _dnsname_match2(pattern: str, hostname: str) -> bool:
        """
        Relaxed wildcard matching:
        - Case-insensitive
        - Wildcard '*' may appear anywhere in the left-most label
          (not only as full '*')
        - '*' matches zero or more chars
        - Still requires same number of labels
        """
        pattern = pattern.lower()
        hostname = hostname.lower()

        if pattern == hostname:
            return True

        parts_pat = pattern.split(".")
        parts_host = hostname.split(".")

        if len(parts_pat) != len(parts_host):
            return False

        # turn left-most label into regex
        left_pat = re.escape(parts_pat[0]).replace("\\*", ".*")
        if not re.fullmatch(left_pat, parts_host[0]):
            return False

        # rest must match exactly
        return parts_pat[1:] == parts_host[1:]


class EKUValidator(Validator):
    oid = x509.ExtensionOID.EXTENDED_KEY_USAGE

    def __init__(self, purpose: x509.ObjectIdentifier) -> None:
        self._purpose = purpose

    def __call__(
        self,
        verifier: x509.Verifier,
        ee: x509.Certificate,
        extension: x509.Extension[x509.ExtendedKeyUsage],
    ) -> None:
        purpose = self._purpose
        eku = extension.value

        if purpose not in eku:
            raise AlertBadCertificate(f"EKU {ee} not allowed by policy")
