#!/bin/env python3
## Intercepting HTTP(S) proxy for shellfire.
## Point a browser at this proxy and it will capture requests for the
## session, which can then be used to seed exploit parameters (see the
## `proxy use` command in commands.py).
##
## Plain HTTP is captured directly. HTTPS is captured via a man-in-the-middle:
## a local CA is generated once and per-host leaf certs are minted on the fly.
## The CA cert must be trusted by your browser (see `proxy ca`).

import datetime
import ipaddress
import os
import socket
import ssl
import sys
import threading
import urllib.parse

import requests

from shellfire.config import cfg, state

## hop-by-hop headers that must not be forwarded verbatim (RFC 7230 6.1),
## plus encoding headers we let `requests` normalize for us.
HOP_BY_HOP = {
    'connection', 'keep-alive', 'proxy-authenticate', 'proxy-authorization',
    'te', 'trailers', 'transfer-encoding', 'upgrade',
    'content-length', 'content-encoding', 'accept-encoding',
}

## where we keep the CA and minted leaf certs
CA_DIR = os.path.expanduser("~/.config/shellfire/ca")
CA_CERT = os.path.join(CA_DIR, "shellfire-ca.crt")
CA_KEY = os.path.join(CA_DIR, "shellfire-ca.key")
LEAF_DIR = os.path.join(CA_DIR, "certs")

## in-memory caches, keyed by host
_ctx_cache = {}
_ctx_lock = threading.Lock()


############################################################
## Certificate authority

def ensure_ca():
  """Generate the shellfire CA if it does not already exist. Returns the
  path to the CA certificate the user should trust in their browser."""
  if os.path.isfile(CA_CERT) and os.path.isfile(CA_KEY):
    return CA_CERT

  from cryptography import x509
  from cryptography.x509.oid import NameOID
  from cryptography.hazmat.primitives import hashes, serialization
  from cryptography.hazmat.primitives.asymmetric import rsa

  os.makedirs(CA_DIR, exist_ok=True)
  key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
  name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "ShellFire Proxy CA")])
  now = datetime.datetime.now(datetime.timezone.utc)
  cert = (
      x509.CertificateBuilder()
      .subject_name(name)
      .issuer_name(name)
      .public_key(key.public_key())
      .serial_number(x509.random_serial_number())
      .not_valid_before(now - datetime.timedelta(days=1))
      .not_valid_after(now + datetime.timedelta(days=3650))
      .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
      .add_extension(
          x509.KeyUsage(
              digital_signature=True, key_cert_sign=True, crl_sign=True,
              content_commitment=False, key_encipherment=False,
              data_encipherment=False, key_agreement=False,
              encipher_only=False, decipher_only=False),
          critical=True)
      .sign(key, hashes.SHA256())
  )
  with open(CA_KEY, "wb") as f:
    f.write(key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.TraditionalOpenSSL,
        serialization.NoEncryption()))
  with open(CA_CERT, "wb") as f:
    f.write(cert.public_bytes(serialization.Encoding.PEM))
  return CA_CERT


def _mint_leaf(host):
  """Create (and cache to disk) a leaf cert for `host` signed by our CA.
  Returns the path to a PEM file containing the leaf cert and its key."""
  os.makedirs(LEAF_DIR, exist_ok=True)
  ## sanitize host for use as a filename
  safe = host.replace(":", "_").replace("/", "_")
  leaf_path = os.path.join(LEAF_DIR, safe + ".pem")
  if os.path.isfile(leaf_path):
    return leaf_path

  from cryptography import x509
  from cryptography.x509.oid import NameOID
  from cryptography.hazmat.primitives import hashes, serialization
  from cryptography.hazmat.primitives.asymmetric import rsa

  ensure_ca()
  with open(CA_KEY, "rb") as f:
    ca_key = serialization.load_pem_private_key(f.read(), password=None)
  with open(CA_CERT, "rb") as f:
    ca_cert = x509.load_pem_x509_certificate(f.read())

  ## a subject alt name may be a DNS name or an IP address
  try:
    san = x509.IPAddress(ipaddress.ip_address(host))
  except ValueError:
    san = x509.DNSName(host)

  key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
  now = datetime.datetime.now(datetime.timezone.utc)
  cert = (
      x509.CertificateBuilder()
      .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, host)]))
      .issuer_name(ca_cert.subject)
      .public_key(key.public_key())
      .serial_number(x509.random_serial_number())
      .not_valid_before(now - datetime.timedelta(days=1))
      ## keep under the 398-day limit browsers enforce for server certs
      .not_valid_after(now + datetime.timedelta(days=397))
      .add_extension(x509.SubjectAlternativeName([san]), critical=False)
      .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
      .add_extension(
          x509.ExtendedKeyUsage([x509.oid.ExtendedKeyUsageOID.SERVER_AUTH]),
          critical=False)
      .sign(ca_key, hashes.SHA256())
  )
  with open(leaf_path, "wb") as f:
    f.write(cert.public_bytes(serialization.Encoding.PEM))
    f.write(key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.TraditionalOpenSSL,
        serialization.NoEncryption()))
  return leaf_path


def _server_ctx(host):
  """Return a cached server-side SSLContext presenting a cert for `host`."""
  with _ctx_lock:
    if host in _ctx_cache:
      return _ctx_cache[host]
  leaf_path = _mint_leaf(host)
  ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
  ctx.load_cert_chain(leaf_path)
  with _ctx_lock:
    _ctx_cache[host] = ctx
  return ctx


############################################################
## HTTP parsing helpers

def _recv_headers(sock):
  """Read from `sock` up to and including the end of the HTTP headers.
  Returns (header_bytes, leftover_body_bytes) or (None, None) on EOF."""
  data = b""
  while b"\r\n\r\n" not in data:
    chunk = sock.recv(4096)
    if not chunk:
      return None, None
    data += chunk
    if len(data) > 1024 * 1024:
      ## refuse absurd header blocks
      break
  head, _, rest = data.partition(b"\r\n\r\n")
  return head, rest


def _parse_request(head):
  """Parse a raw HTTP header block into (method, target, version, headers).
  `headers` preserves order and original casing."""
  lines = head.decode("iso-8859-1").split("\r\n")
  method, target, version = lines[0].split(" ", 2)
  headers = []
  for line in lines[1:]:
    if not line:
      continue
    k, _, v = line.partition(":")
    headers.append((k.strip(), v.strip()))
  return method, target, version, headers


def _header_get(headers, name):
  for k, v in headers:
    if k.lower() == name.lower():
      return v
  return None


def _read_body(headers, leftover, sock):
  """Read a request body given already-buffered `leftover` bytes."""
  length = _header_get(headers, "Content-Length")
  if not length:
    return leftover
  try:
    length = int(length)
  except ValueError:
    return leftover
  body = leftover
  while len(body) < length:
    chunk = sock.recv(4096)
    if not chunk:
      break
    body += chunk
  return body[:length]


############################################################
## Request capture + forwarding

def _capture(method, url, headers, body):
  """Record a captured request in session state."""
  parsed = urllib.parse.urlparse(url)
  entry = {
      "method": method,
      "url": url,
      "host": parsed.netloc,
      "path": parsed.path or "/",
      "query": parsed.query,
      "headers": {k: v for k, v in headers},
      "cookie": _header_get(headers, "Cookie") or "",
      "body": body.decode("utf-8", "replace") if body else "",
      "content_type": _header_get(headers, "Content-Type") or "",
  }
  state.captured_requests.append(entry)
  if state.args and getattr(state.args, "debug", False):
    sys.stderr.write("[P] captured %s %s\n" % (method, url))
  return entry


def _forward(method, url, headers, body):
  """Forward a captured request to the origin and return a raw HTTP
  response (bytes) suitable for writing back to the client."""
  ## refuse to forward to ourselves (e.g. the browser was pointed at the
  ## proxy address directly), which would loop back into this server.
  parsed = urllib.parse.urlparse(url)
  if parsed.hostname in ("127.0.0.1", "localhost", "::1") \
      and (parsed.port or 80) == cfg.proxy_port:
    msg = ("HTTP/1.1 421 Misdirected Request\r\n"
           "Content-Type: text/plain\r\n"
           "Connection: close\r\n\r\n"
           "shellfire proxy: refusing to forward a request to myself")
    return msg.encode("utf-8", "replace")

  fwd = {k: v for k, v in headers if k.lower() not in HOP_BY_HOP}
  try:
    resp = requests.request(
        method, url,
        headers=fwd,
        data=body if body else None,
        allow_redirects=False,
        verify=False,
        timeout=30,
        ## never forward through an ambient proxy: the browser points its
        ## proxy env at us, so honoring it here would loop back into this
        ## server and exhaust file descriptors.
        proxies={"http": None, "https": None},
    )
  except Exception as e:
    msg = ("HTTP/1.1 502 Bad Gateway\r\n"
           "Content-Type: text/plain\r\n"
           "Connection: close\r\n\r\n"
           "shellfire proxy: upstream error: %s" % e)
    return msg.encode("utf-8", "replace")

  ## requests has already decoded any content/transfer encoding, so we
  ## rebuild the response with a plain Content-Length and no chunking.
  content = resp.content
  reason = resp.reason or ""
  out = ["HTTP/1.1 %d %s" % (resp.status_code, reason)]
  for k, v in resp.headers.items():
    if k.lower() in HOP_BY_HOP:
      continue
    out.append("%s: %s" % (k, v))
  out.append("Content-Length: %d" % len(content))
  out.append("Connection: close")
  head = ("\r\n".join(out) + "\r\n\r\n").encode("iso-8859-1")
  return head + content


############################################################
## Connection handlers

def _handle_plain(conn, method, target, headers, leftover):
  """Handle an absolute-form plain HTTP proxy request."""
  body = _read_body(headers, leftover, conn)
  _capture(method, target, headers, body)
  conn.sendall(_forward(method, target, headers, body))


def _handle_connect(conn, target):
  """Handle an HTTPS CONNECT: MITM the tunnel and capture requests."""
  host = target.split(":")[0]
  conn.sendall(b"HTTP/1.1 200 Connection established\r\n\r\n")
  try:
    ctx = _server_ctx(host)
    tls = ctx.wrap_socket(conn, server_side=True)
  except Exception as e:
    if state.args and getattr(state.args, "debug", False):
      sys.stderr.write("[!] proxy TLS handshake failed for %s: %s\n" % (host, e))
    return

  try:
    ## a browser may reuse the tunnel for several requests
    while True:
      head, leftover = _recv_headers(tls)
      if not head:
        break
      method, path, _version, headers = _parse_request(head)
      body = _read_body(headers, leftover, tls)
      ## reconstruct the absolute URL from the Host header
      hdr_host = _header_get(headers, "Host") or host
      url = "https://%s%s" % (hdr_host, path)
      _capture(method, url, headers, body)
      tls.sendall(_forward(method, url, headers, body))
      ## we force Connection: close on responses, so stop after one
      break
  finally:
    try:
      tls.close()
    except Exception:
      pass


def _handle_client(conn):
  try:
    conn.settimeout(30)
    head, leftover = _recv_headers(conn)
    if not head:
      return
    method, target, _version, headers = _parse_request(head)
    if method.upper() == "CONNECT":
      _handle_connect(conn, target)
    else:
      _handle_plain(conn, method, target, headers, leftover)
  except Exception as e:
    if state.args and getattr(state.args, "debug", False):
      sys.stderr.write("[!] proxy client error: %s\n" % e)
  finally:
    try:
      conn.close()
    except Exception:
      pass


def proxy_server(port):
  """Accept loop for the intercepting proxy. Runs until state.proxy_running
  is cleared. Mirrors the style of commands.http_server."""
  sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
  sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
  sock.settimeout(1)
  try:
    sock.bind(('', port))
    sock.listen(50)
  except Exception as e:
    sys.stderr.write("[!] Unable to start proxy on port %s: %s\n" % (port, e))
    state.proxy_running = False
    return
  while state.proxy_running is True:
    try:
      conn, _addr = sock.accept()
    except socket.timeout:
      continue
    except Exception as e:
      if state.args and getattr(state.args, "debug", False):
        sys.stderr.write("[!] proxy accept error: %s\n" % e)
      continue
    t = threading.Thread(target=_handle_client, args=(conn,))
    t.daemon = True
    t.start()
  try:
    sock.close()
  except Exception:
    pass
  sys.stdout.write("[*] Proxy stopped\n")
