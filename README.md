# Gentoo LXC Dashboard

A small C11, self-hosted web UI for LXC containers on Gentoo/OpenRC. No Python, Node.js, systemd, or external frontend runtime is required.

> **Status: early MVP.** The dashboard implements login/session handling, container discovery/status, lifecycle actions, and a persistent PTY shell over WebSocket. The terminal UI is a basic text view rather than a full xterm.js emulator; terminal resize and rich ANSI/curses rendering are not implemented. Streamed template-download progress, cgroup/network time-series graphs, log viewer, host overview, and a non-blocking job queue are still outstanding. This has not yet been validated on a Gentoo host; do not treat it as production-ready.

## Build on Gentoo

```sh
emerge --ask app-containers/lxc sys-libs/libxcrypt dev-libs/openssl
make
make debug
```

The build uses libc, libxcrypt, OpenSSL (for the WebSocket handshake), and libutil (for `forkpty`). `make debug` builds with AddressSanitizer and UndefinedBehaviorSanitizer. The dashboard source and embedded HTML/CSS/JS are in `src/main.c`; the PTY/WebSocket transport is in `src/terminal.inc`.

Install:

```sh
install -Dm0755 lxc-dashboard /usr/local/bin/lxc-dashboard
install -Dm0644 lxc-dashboard.init /etc/init.d/lxc-dashboard
install -Dm0644 lxc-dashboard.conf /etc/conf.d/lxc-dashboard
install -d -o root -g root -m 0700 /etc/lxc-dashboard
/usr/local/bin/lxc-dashboard --set-password /etc/lxc-dashboard/auth
chown root:root /etc/lxc-dashboard/auth
chmod 0600 /etc/lxc-dashboard/auth
```

The password command prompts interactively and stores a yescrypt hash, not the plaintext password. Use a password of at least 12 characters.

## Run

Foreground smoke test (loopback only):

```sh
/usr/local/bin/lxc-dashboard --bind 127.0.0.1 --port 8088 --auth /etc/lxc-dashboard/auth
```

Open `http://127.0.0.1:8088` on the host, or use an SSH tunnel from your workstation:

```sh
ssh -L 8088:127.0.0.1:8088 user@SERVER_IP
```

To expose it on a private LAN, explicitly set a server LAN address in `/etc/conf.d/lxc-dashboard`, then:

```sh
rc-update add lxc-dashboard default
rc-service lxc-dashboard start
rc-service lxc-dashboard status
```

The default bind is `127.0.0.1`, not `0.0.0.0`.

## Security

This process invokes privileged LXC commands. An authenticated user can control workloads and may effectively gain root-level access to their contents. Keep it on a trusted network. **Never expose it directly to the internet**; use a VPN or a correctly configured TLS reverse proxy for remote access. The built-in server uses plain HTTP, so credentials and session cookies are not encrypted in transit.

The HTTP implementation is intentionally minimal and handles requests synchronously; each terminal WebSocket gets a separate worker process so an open terminal does not block ordinary dashboard requests. The WebSocket and PTY code is purpose-built rather than a mature protocol library, so do not use it as a multi-user or internet-facing service.

## Test checklist

- [ ] Build with `make` using the target Gentoo toolchain (including OpenSSL development headers).
- [ ] Build with `make debug` and exercise login/list/actions.
- [ ] Verify the auth file is root-owned and mode `0600`.
- [ ] Verify unauthenticated API and WebSocket requests receive HTTP 401.
- [ ] Connect to a disposable running container and verify persistent shell state, input/output, Ctrl+C, disconnect cleanup, and reconnect.
- [ ] Verify container names outside `[A-Za-z0-9][A-Za-z0-9_-]{0,62}` are rejected.
- [ ] Use a disposable container to test start, stop, freeze, unfreeze, and destroy.
- [ ] Check service logs at `/var/log/lxc-dashboard.log`.
- [ ] Confirm the service binds only to the configured address.

## Design choice

This first cut uses a small purpose-built POSIX socket HTTP server to minimize dependencies and keep the code auditable. That also means it lacks mature HTTP/WebSocket handling; the full specification should replace or extend this layer with a well-tested embedded HTTP/WebSocket implementation before adding terminal support.
