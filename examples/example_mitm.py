from __future__ import annotations

import ipaddress
import os
import typing
from functools import lru_cache

import certifi
import dns
import dns.asyncresolver
import dns.rdatatype
import dns.rdtypes
import dns.rdtypes.svcbbase
from cryptography import x509
from mitmproxy import connection, ctx, tls
from mitmproxy.addons import tlsconfig
from mitmproxy.net import tls as net_tls
from OpenSSL import SSL
from OpenSSL.crypto import X509 as OpenSSL_X509  # noqa: N811

from simple_tls import tls as stls
from simple_tls.crypto import verification


async def resolve_ech(hostname: str) -> bytes | None:
    resolver = dns.asyncresolver.Resolver()
    t = dns.rdatatype.HTTPS
    try:
        resp = await resolver.resolve(hostname, t, tcp=False)
    except Exception:
        pass
    else:
        for r in resp:
            for k, v in r.params.items():
                if isinstance(v, dns.rdtypes.svcbbase.ECHParam):
                    return v.ech
    return None


@lru_cache(maxsize=256)
def load_cert_chain(certfile: str) -> stls.TLSCredential:
    return stls.TLSCredential.from_certfile(certfile)


@lru_cache(maxsize=256)
def load_castore(
    ca_path: str | None, ca_pemfile: str | None
) -> verification.Store:
    return stls.load_castore(capath=ca_path, cafile=ca_pemfile)


class SSLConnection:
    def __init__(
        self,
        method: net_tls.Method,
        min_version: net_tls.Version,
        max_version: net_tls.Version,
        cipher_list: tuple[str, ...] | None,
        ecdh_curve: str | None,
        verify: net_tls.Verify,
        ca_path: str | None,
        ca_pemfile: str | None,
        certfile: str | None,
        legacy_server_connect: bool,
    ) -> None:
        config: dict[str, typing.Any] = {}

        if min_version != net_tls.Version.UNBOUNDED:
            config["minimum_version"] = min_version.value

        if max_version != net_tls.Version.UNBOUNDED:
            config["maximum_version"] = max_version.value

        if verify.value == SSL.VERIFY_PEER:
            self._verify_mode = stls.VerifyMode.CERT_REQUIRED
        else:
            self._verify_mode = stls.VerifyMode.CERT_NONE

        if certfile:
            config["credential"] = load_cert_chain(certfile)

        if ecdh_curve is not None:
            try:
                group = stls.NamedGroup[ecdh_curve]
            except KeyError:
                pass
            else:
                config["supported_groups"] = [group]

        config["legacy_server_connect"] = legacy_server_connect
        config["castore"] = load_castore(
            ca_path=ca_path, ca_pemfile=ca_pemfile
        )

        self._method = method
        self._config = config
        self._conn: stls.TLSConnection | None = None
        self._server_hostname: bytes | None = None

    def _new_session_handler(self, session: stls.TLSSession) -> None:
        pass

    def set_connect_state(self) -> None:
        if (
            self._verify_mode != stls.VerifyMode.CERT_NONE
            and self._server_hostname
        ):
            check_hostname = True
        else:
            check_hostname = False

        config = stls.TLSConfiguration(
            is_server=False,
            protocol=stls.Protocol.TLS,
            check_hostname=check_hostname,
            server_hostname=self._server_hostname,
            verify_mode=self._verify_mode,
            **self._config,
        )
        self._conn = stls.TLSConnection(config)

    def set_accept_state(self) -> None:
        config = stls.TLSConfiguration(
            is_server=False,
            protocol=stls.Protocol.TLS,
            verify_mode=self._verify_mode,
            **self._config,
        )
        self._conn = stls.TLSConnection(config)

    def set_alpn_protos(self, protos: typing.Sequence[bytes]) -> None:
        self._config["alpn_protocols"] = protos

    def set_tlsext_host_name(self, host_name: bytes) -> None:
        self._server_hostname = host_name

    def set_ech_configs(self, ech_config: bytes | None) -> None:
        self._config["ech_configs"] = ech_config

    def bio_read(self, bufsiz: int) -> bytes:
        if self._conn is None:
            raise TypeError("connection state not set")
        try:
            return self._conn.bio_read(bufsiz)
        except stls.TLSWantReadError:
            raise SSL.WantReadError() from None

    def bio_write(self, buf: bytes) -> None:
        if self._conn is None:
            raise TypeError("connection state not set")
        return self._conn.bio_write(buf)

    def sendall(self, buf: bytes, flags: int = 0) -> None:
        if flags != 0:
            raise NotImplementedError("flags can only be 0")
        if self._conn is None:
            raise TypeError("connection state not set")

        buf_len = len(buf)
        n = 0
        view = memoryview(buf)
        while n < buf_len:
            try:
                n += self._conn.write(view[n:])
            except stls.TLSWantReadError:
                raise SSL.WantReadError() from None
            except stls.TLSEOFError:
                raise SSL.ZeroReturnError() from None

    def recv(self, bufsiz: int, flags: int | None = None) -> bytes:
        if self._conn is None:
            raise TypeError("connection state not set")
        try:
            data = self._conn.read(bufsiz)
        except stls.TLSWantReadError:
            raise SSL.WantReadError() from None
        except stls.TLSEOFError:
            raise SSL.ZeroReturnError() from None
        return data

    def get_shutdown(self) -> int:
        return SSL.SENT_SHUTDOWN

    def do_handshake(self) -> None:
        if self._conn is None:
            raise TypeError("connection state not set")
        try:
            self._conn.do_handshake()
        except stls.TLSWantReadError:
            raise SSL.WantReadError() from None
        except stls.TLSRemoteAlert as exc:
            raise SSL.Error(exc) from exc
        except stls.TLSLocalAlert as exc:
            raise SSL.Error(exc) from exc

    def get_peer_certificate(
        self, as_cryptography: bool = False
    ) -> OpenSSL_X509 | x509.Certificate | None:
        if self._conn is None:
            raise TypeError("connection state not set")

        chain = self._conn.get_unverified_chain()
        if chain:
            certificate = chain[0]
            if as_cryptography:
                return certificate
            return OpenSSL_X509.from_cryptography(certificate)
        return None

    def get_peer_cert_chain(
        self, as_cryptography: bool = False
    ) -> list[OpenSSL_X509] | list[x509.Certificate]:
        if self._conn is None:
            raise TypeError("connection state not set")

        chain = self._conn.get_unverified_chain()
        if as_cryptography:
            return chain
        return [OpenSSL_X509.from_cryptography(c) for c in chain]

    def get_alpn_proto_negotiated(self) -> bytes | None:
        if self._conn is None:
            raise TypeError("connection state not set")
        return self._conn.selected_alpn_protocol()

    def get_cipher_name(self) -> str | None:
        if self._conn is None:
            raise TypeError("connection state not set")

        c = self._conn.cipher()
        if c:
            return c.name
        return None

    def get_protocol_version_name(self) -> str:
        if self._conn is None:
            raise TypeError("connection state not set")
        return self._conn.version()

    def ech_accepted(self) -> bool:
        if self._conn is None:
            raise TypeError("connection state not set")
        return self._conn.ech_accepted()

    def get_retry_config(self) -> bytes | None:
        if self._conn is None:
            raise TypeError("connection state not set")
        return self._conn.ech_retry_configs(binary_form=True)

    def get_app_data(self) -> bytes:
        """
        Retrieve application data as set by :meth:`set_app_data`.

        :return: The application data
        """
        return self._app_data

    def set_app_data(self, data: bytes) -> None:
        """
        Set application data

        :param data: The application data
        :return: None
        """
        self._app_data = data

    def shutdown(self) -> None:
        if self._conn is None:
            raise TypeError("connection state not set")
        self._conn.shutdown()
        self._conn = None


class CustomSSLContext:
    def __init__(self) -> None:
        self.ech_configs: dict[str, bytes | None] = {}

    async def tls_start_server(self, tls_start: tls.TlsData) -> None:
        if tls_start.is_dtls:
            return

        client = typing.cast(connection.Client, tls_start.context.client)
        server = typing.cast(connection.Server, tls_start.conn)
        assert server.address is not None
        assert isinstance(server, connection.Server)

        if ctx.options.ssl_insecure:
            verify = net_tls.Verify.VERIFY_NONE
        else:
            verify = net_tls.Verify.VERIFY_PEER

        if server.sni is None:
            server.sni = client.sni or server.address[0]

        if not server.alpn_offers:
            if client.alpn_offers:
                if ctx.options.http2:
                    server.alpn_offers = tuple(client.alpn_offers)
                else:
                    server.alpn_offers = tuple(
                        x for x in client.alpn_offers if x != b"h2"
                    )
            else:
                server.alpn_offers = ()

        cipher_server: str = ctx.options.ciphers_server
        if not server.cipher_list and cipher_server:
            server.cipher_list = cipher_server.split(":")

        cipher_list = server.cipher_list or tlsconfig._default_ciphers(
            net_tls.Version[ctx.options.tls_version_server_min]
        )

        client_cert: str | None = None
        if ctx.options.client_certs:
            client_certs = os.path.expanduser(ctx.options.client_certs)

            if not os.path.isfile(client_certs):
                server_name: str = server.sni or server.address[0]
                p = os.path.join(client_certs, f"{server_name}.pem")

                if os.path.isfile(p):
                    client_cert = p

        if ctx.options.ssl_verify_upstream_trusted_confdir:
            ca_pemfile = ctx.options.ssl_verify_upstream_trusted_confdir
        else:
            ca_pemfile = certifi.where()

        ssl_conn = SSLConnection(
            method=net_tls.Method.TLS_CLIENT_METHOD,
            min_version=net_tls.Version[ctx.options.tls_version_server_min],
            max_version=net_tls.Version[ctx.options.tls_version_server_max],
            cipher_list=tuple(cipher_list),
            ecdh_curve=ctx.options.tls_ecdh_curve_server,
            verify=verify,
            ca_path=ctx.options.ssl_verify_upstream_trusted_confdir,
            ca_pemfile=ca_pemfile,
            certfile=client_cert,
            legacy_server_connect=ctx.options.ssl_insecure,
        )

        if server.sni:
            try:
                ipaddress.ip_address(server.sni).packed
            except ValueError:
                try:
                    ech_config = self.ech_configs[server.sni]
                except KeyError:
                    ech_config = await resolve_ech(server.sni)
                    self.ech_configs[server.sni] = ech_config

                ssl_conn.set_ech_configs(ech_config)

                host_name = server.sni.encode("idna")
                ssl_conn.set_tlsext_host_name(host_name)

        elif verify is not stls.VerifyMode.CERT_NONE:
            raise ValueError(
                "Cannot validate certificate hostname without SNI"
            )

        if server.alpn_offers:
            ssl_conn.set_alpn_protos(server.alpn_offers)

        ssl_conn.set_connect_state()
        tls_start.ssl_conn = typing.cast(SSL.Connection, ssl_conn)

    def tls_failed_server(self, tls_data: tls.TlsData) -> None:
        if not isinstance(tls_data.ssl_conn, SSLConnection):
            return

        ssl_conn = typing.cast(SSLConnection, tls_data.ssl_conn)
        sni = tls_data.conn.sni

        if sni:
            ech_configs = ssl_conn.get_retry_config()

            if ech_configs is not None:
                self.ech_configs[sni] = ech_configs
                tls_data.context.server.error = None


addons = [CustomSSLContext()]


if __name__ == "__main__":
    from mitmproxy.tools.main import mitmweb

    args = [f"-s {__file__}"]
    try:
        mitmweb(args)
    except Exception as e:
        print(e)

    input("Please ENTER to exit.")
