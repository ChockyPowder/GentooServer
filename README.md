# Gentoo LXC Dashboard

A small C11 web dashboard for managing Linux LXC containers on Gentoo/OpenRC. It is intentionally LAN-only and has no Node/Python runtime dependency.

## Current implementation scope

The initial implementation is a compact HTTP server with password login, server-side expiring sessions, strict container-name validation, container listing/status, and argv-only lifecycle commands. It serves the UI from a compiled-in asset header. This is a foundation, not yet the complete feature set described in the project request: interactive WebSocket/PTTY terminal, streamed download-template progress, detailed cgroup/network graphs, and full host overview are not implemented yet.

## Build (Gentoo)

```sh
emerge --ask sys-apps/lxc sys-libs/libxcrypt
make
install -Dm0755 lxc-dashboard /usr/local/bin/lxc-dashboard
install -Dm0644 lxc-dashboard.init /etc/init.d/lxc-dashboard
```

The build uses only libc and libcrypt; the server does not need a framework or runtime. Run `make debug` for an ASan/UBSan build.

## Credentials and run

Create a credential file (mode 0600) with a username and a yescrypt password hash:

```sh
install -d -m 0700 /etc/lxc-dashboard
/usr/local/bin/lxc-dashboard --set-password /etc/lxc-dashboard/auth
chown root:root /etc/lxc-dashboard/auth
chmod 0600 /etc/lxc-dashboard/auth
```

Run in the foreground for initial testing:

```sh
/usr/local/bin/lxc-dashboard --bind 127.0.0.1 --port 8088 --auth /etc/lxc-dashboard/auth
```

Use a private LAN address only if you explicitly configure one, e.g. `--bind 192.168.1.10`. Open `http://SERVER_IP:8088`.

## OpenRC

Edit `/etc/conf.d/lxc-dashboard` to set `DASHBOARD_OPTS`, then:

```sh
rc-update add lxc-dashboard default
rc-service lxc-dashboard start
```

## Security warning

This application runs privileged LXC management commands. Anyone who can authenticate can control or destroy containers, which is effectively root-level access to the workloads. Keep it on a trusted private network; **do not expose it directly to the internet**. For remote access, use a properly configured TLS reverse proxy/VPN. HTTP on the LAN does not encrypt credentials.

## Test checklist

- [ ] Log in and verify unauthenticated API requests are rejected.
- [ ] Confirm existing containers and states are listed.
- [ ] Start/stop/freeze/unfreeze a disposable container.
- [ ] Verify invalid container names are rejected.
- [ ] Verify destroy requires an explicit confirmation in the UI.
- [ ] Run the ASan/UBSan build and exercise login/actions.
- [ ] Confirm the service binds only to the configured address.

## Implementation note

A small purpose-built POSIX HTTP server was selected to keep the binary and dependencies minimal on Gentoo. It is easier to audit than bringing in a large web framework, but it does not yet provide WebSocket support; terminal access is therefore outside this initial version.