# simple-tls

A custom, lightweight implementation of the TLS protocol (supporting TLS 1.0 through TLS 1.3) built entirely in Python.

`simple-tls` is designed to be a seamless, drop-in replacement for Python's built-in `ssl` module, allowing you to utilize advanced TLS features without having to rewrite your existing socket logic.

## ✨ Features

* **Broad Protocol Support:** Fully implements TLS 1.0, 1.1, 1.2, and 1.3.
* **Familiar API:** Mirrors the native Python `ssl` module API for effortless integration.
* **Encrypted Client Hello (ECH):** Modern privacy features to keep hostnames hidden during the handshake.
* **Early Data (0-RTT):** Faster connection resumptions for performance-critical applications.
* **Customizable Handshakes:** Deep-level control over the TLS handshake process that the standard library doesn't expose.

## 📦 Installation

**Requirements:**

* Python 3.10 or higher
* `cryptography` 42.0.0 or higher

You can install the package via pip:

```bash
pip install simple-tls

```

## 🚀 Quick Start (Manual)

Because `simple-tls` maps directly to the standard library's interface, upgrading your existing sockets to use custom TLS is as easy as changing your import statement.

Here is a complete example of connecting securely to a website using `simple-tls`:

```python
import socket
from simple_tls import pyssl

hostname = 'www.python.org'
port = 443

# 1. Create a secure default context using simple-tls
# This automatically loads the system's trusted CA certificates
context = pyssl.SSLContext()

# 2. Create a standard TCP socket
with socket.create_connection((hostname, port)) as sock:
    # 3. Wrap the socket to secure it
    # server_hostname is required for SNI (Server Name Indication) and hostname verification
    with context.wrap_socket(sock, server_hostname=hostname) as ssock:
        print(f"Connected to {hostname} securely!")
        print(f"TLS Version: {ssock.version()}")
        print(f"Cipher Suite: {ssock.cipher()}\n")
        
        # 4. Send encrypted data (A simple HTTP GET request)
        request = f"GET / HTTP/1.1\r\nHost: {hostname}\r\nConnection: close\r\n\r\n"
        ssock.sendall(request.encode('utf-8'))
        
        # 5. Receive the encrypted response
        response = b""
        while True:
            data = ssock.recv(1024)
            if not data:
                break
            response += data
            
        print("Received headers:")
        print(response.split(b"\r\n\r\n")[0].decode('utf-8'))
```

## 📄 License

This project is licensed under the MIT License.
