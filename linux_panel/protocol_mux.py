"""Small TCP protocol multiplexer for a single HTTP/HTTPS public port.

Plain HTTP requests receive a 308 redirect to the exact same host, port, path,
and query over HTTPS. TLS connections are passed through byte-for-byte to the
local Flask-SocketIO TLS listener. This keeps HTTP redirects and HTTPS on the
same public port without exposing the internal TLS backend port.
"""
from __future__ import annotations

import re
import select
import socket
import threading
from urllib.parse import urlsplit

_HEADER_LIMIT = 64 * 1024
_SNIFF_TIMEOUT = 10
_HTTP_HEADER_TIMEOUT = 5
_HOST_RE = re.compile(
    r"(?i)(?:[a-z0-9](?:[a-z0-9.\-]*[a-z0-9])?|\[[0-9a-f:.%]+\])(?:\:[0-9]{1,5})?\Z"
)


def choose_loopback_port() -> int:
    """Ask the OS for a currently available ephemeral TCP port on loopback."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def create_listener(host: str, port: int, backlog: int = 256) -> socket.socket:
    """Bind the externally visible port, returning the listening socket."""
    candidates = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM, flags=socket.AI_PASSIVE)
    last_error = None
    seen = set()
    for family, socktype, proto, _canonname, sockaddr in candidates:
        key = (family, sockaddr)
        if key in seen:
            continue
        seen.add(key)
        listener = socket.socket(family, socktype, proto)
        try:
            listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            if family == socket.AF_INET6:
                try:
                    listener.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
                except OSError:
                    pass
            listener.bind(sockaddr)
            listener.listen(backlog)
            return listener
        except OSError as exc:
            last_error = exc
            listener.close()
    raise OSError(f"无法监听 {host}:{port}: {last_error}")


def _send_bad_request(client: socket.socket, status: str = "400 Bad Request") -> None:
    body = b"Bad Request\n"
    response = (
        f"HTTP/1.1 {status}\r\n"
        "Connection: close\r\n"
        "Content-Type: text/plain; charset=utf-8\r\n"
        f"Content-Length: {len(body)}\r\n\r\n"
    ).encode("ascii") + body
    try:
        client.sendall(response)
    except OSError:
        pass


def _read_http_headers(client: socket.socket, first: bytes) -> bytes | None:
    client.settimeout(_HTTP_HEADER_TIMEOUT)
    data = bytearray(first)
    while b"\r\n\r\n" not in data:
        if len(data) >= _HEADER_LIMIT:
            return None
        try:
            chunk = client.recv(min(4096, _HEADER_LIMIT - len(data)))
        except (OSError, TimeoutError):
            return None
        if not chunk:
            return None
        data.extend(chunk)
    return bytes(data)


def _safe_host(headers: bytes, client: socket.socket) -> str | None:
    host_value = None
    for line in headers.split(b"\r\n")[1:]:
        if not line:
            break
        name, sep, value = line.partition(b":")
        if sep and name.strip().lower() == b"host":
            try:
                host_value = value.strip().decode("ascii")
            except UnicodeDecodeError:
                return None
            break
    if not host_value:
        # HTTP/1.0 clients may omit Host. Prefer the accepted socket's local IP.
        try:
            addr = client.getsockname()
            host_value = f"[{addr[0]}]" if ":" in addr[0] else addr[0]
        except OSError:
            return None
    if not _HOST_RE.fullmatch(host_value):
        return None
    port_match = re.search(r":([0-9]{1,5})\Z", host_value)
    if port_match and not 1 <= int(port_match.group(1)) <= 65535:
        return None
    return host_value


def _redirect_http(client: socket.socket, first: bytes) -> None:
    headers = _read_http_headers(client, first)
    if not headers:
        _send_bad_request(client)
        return
    request_line = headers.split(b"\r\n", 1)[0]
    parts = request_line.split(b" ")
    if len(parts) < 3 or not parts[0] or not parts[2].startswith(b"HTTP/"):
        _send_bad_request(client)
        return

    try:
        target = parts[1].decode("ascii")
    except UnicodeDecodeError:
        _send_bad_request(client)
        return

    host = _safe_host(headers, client)
    if not host:
        _send_bad_request(client)
        return

    # Normal browser requests use origin-form (/path?query). Also tolerate
    # absolute-form request targets while retaining a safe path and query.
    if target.startswith("/"):
        location_path = target
    elif target == "*":
        location_path = "/"
    else:
        parsed = urlsplit(target)
        if parsed.scheme.lower() in ("http", "https") and parsed.netloc:
            location_path = parsed.path or "/"
            if parsed.query:
                location_path += "?" + parsed.query
        else:
            _send_bad_request(client)
            return

    # Host is strictly validated above, so it cannot inject response headers.
    location = f"https://{host}{location_path}"
    response = (
        "HTTP/1.1 308 Permanent Redirect\r\n"
        f"Location: {location}\r\n"
        "Cache-Control: no-store\r\n"
        "Connection: close\r\n"
        "Content-Length: 0\r\n\r\n"
    ).encode("ascii")
    try:
        client.sendall(response)
    except OSError:
        pass


def _pipe(source: socket.socket, destination: socket.socket) -> None:
    try:
        while True:
            data = source.recv(64 * 1024)
            if not data:
                break
            destination.sendall(data)
    except (OSError, TimeoutError):
        pass
    finally:
        try:
            destination.shutdown(socket.SHUT_WR)
        except OSError:
            pass


def _relay_tls(client: socket.socket, first: bytes, backend: tuple[str, int]) -> None:
    upstream = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        upstream.settimeout(5)
        upstream.connect(backend)
        upstream.sendall(first)
        upstream.settimeout(None)
        client.settimeout(None)

        outbound = threading.Thread(target=_pipe, args=(client, upstream), daemon=True)
        inbound = threading.Thread(target=_pipe, args=(upstream, client), daemon=True)
        outbound.start()
        inbound.start()
        # Preserve TCP half-close semantics so protocols such as WebSocket and
        # clients that half-close after a request can still receive the reply.
        outbound.join()
        inbound.join()
    finally:
        upstream.close()


def _handle_client(client: socket.socket, peer, backend: tuple[str, int]) -> None:
    try:
        client.settimeout(_SNIFF_TIMEOUT)
        first = client.recv(1)
        if not first:
            return
        # A TLS handshake starts with a Handshake record (content type 0x16).
        # Pass the consumed byte back into the opaque stream to the TLS backend.
        if first == b"\x16":
            _relay_tls(client, first, backend)
        else:
            _redirect_http(client, first)
    except (OSError, TimeoutError):
        pass
    finally:
        try:
            client.close()
        except OSError:
            pass


def serve(listener: socket.socket, backend_host: str, backend_port: int) -> None:
    """Serve HTTP redirects and proxy TLS streams until the process stops."""
    backend = (backend_host, int(backend_port))
    while True:
        try:
            client, peer = listener.accept()
        except OSError:
            break
        thread = threading.Thread(target=_handle_client, args=(client, peer, backend), daemon=True)
        thread.start()
