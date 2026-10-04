# Running Webjet in Docker

The Webjet image holds `webjetd` (the agent, and `webjetd signer`) and
`webjetctl` (node setup, administration and `webjetctl root`). A container runs one agent: a data node, a
relay, a gateway or a controller. Its roles come from its record in the
network, exactly as with a package install.

## Building the image

```sh
docker build -t webjet .
```

Build arguments:

| Argument | Default | Meaning |
| --- | --- | --- |
| `ANYTLS` | `1` | Include the AnyTLS transport (builds BoringSSL). `0` builds faster and drops it. |
| `VERSION` | `dev` | Value of the `org.opencontainers.image.version` label. |
| `RUST_IMAGE` | `rust:1-bookworm` | Toolchain image for the build stage. |
| `DEBIAN_IMAGE` | `debian:bookworm-slim` | Base of the runtime image. |

Other platforms build with Buildx, for example
`docker buildx build --platform linux/amd64,linux/arm64 -t registry.example/webjet:1.0 --push .`

`docker build --target test -t webjet:test .` builds the same image plus
debugging tools (`ping`, `dig`, `nc`) and the test scripts used by
`docker/e2e.sh`.

## What a container needs

| Requirement | Why |
| --- | --- |
| `--cap-add NET_ADMIN` | Creating the tun interface and its routes. |
| `--device /dev/net/tun` | The tun device. |
| A volume on `/var/lib/webjet` | The identity key and network state. Losing it means re-enrolling the node. |
| `--sysctl net.ipv4.ip_forward=1` | Subnet gateways only. |
| Port 443 TCP and UDP published | Relays and controllers, which others dial. TCP+TLS and UDP+KCP share the port. |

Without NET_ADMIN or the tun device the container can still relay and run a
controller, with `WEBJET_TUN=false`, but it has no overlay interface.

The overlay interface lives in the container's network namespace. To make
the overlay reachable from the host itself, run the container with
`--network host`.

## First start: enrollment

On a fresh volume, the entrypoint enrolls the node before starting the
agent:

```sh
# On an admin machine
webjetctl node enroll --owner infra --name relay-fra --roles data,relay --controller tls:ctl.example.net:443 > relay-fra.enroll

# On the Docker host
docker run -d --name webjet --restart unless-stopped \
  --cap-add NET_ADMIN --device /dev/net/tun \
  -v webjet-state:/var/lib/webjet \
  -p 443:443/tcp -p 443:443/udp \
  -e WEBJET_ENROLL="$(cat relay-fra.enroll)" \
  -e WEBJET_PUBLIC=tls:203.0.113.5:443,kcp:203.0.113.5:443 \
  webjet
```

The enrollment string is single-use and only needed on the first start; later
starts use the state in the volume. `WEBJET_ENROLL_FILE` reads it from a file
instead, which works with Docker and Compose secrets.

To re-key a node (runbook 9), stop the container, run
`docker run --rm -v webjet-state:/var/lib/webjet webjet webjetctl enroll <string>`,
and start it again.

## The first controller of a new network

Runbook 1, with the controller in a container. Create the root key, the admin
account and the genesis on the offline machine as usual, then start the
controller with the genesis:

```sh
docker run -d --name webjet-ctl --restart unless-stopped \
  --cap-add NET_ADMIN --device /dev/net/tun \
  -v webjet-ctl-state:/var/lib/webjet \
  -v "$PWD/genesis.wj:/genesis.wj:ro" \
  -p 443:443/tcp -p 443:443/udp \
  -e WEBJET_GENESIS=/genesis.wj \
  -e WEBJET_PUBLIC=tls:203.0.113.10:443,kcp:203.0.113.10:443 \
  webjet
```

Then continue the runbook inside the container. `webjetctl` there talks to the
agent's control socket. It needs the admin's account key, the one whose
account is in the genesis, so mount the admin's key directory for the
bootstrap and point `WEBJET_KEYS` at it. The directory must be writable,
because `webjetctl` keeps the account's operation counter next to the key.
Add these to the `docker run` above:

```sh
  -v "$HOME/.config/webjet/accounts:/admin-keys" -e WEBJET_KEYS=/admin-keys \
```

Then:

```sh
docker exec -it webjet-ctl webjetctl --account alice account create --name infra --key /admin-keys/infra.pub
docker exec -it webjet-ctl webjetctl --account alice node enroll --owner infra --name ctl-01 --roles data,relay,control --controller tls:203.0.113.10:443
docker exec -it webjet-ctl webjetctl enroll <string>
docker exec -it webjet-ctl webjetctl --account alice controller certify ctl-01
```

`webjetctl` asks for the account passphrase. To have the root sign the
certificate instead, write the request with `webjetctl controller cert-request
--out /var/lib/webjet/ctl-01.req`, copy it out with `docker cp`, sign it with
`webjetctl root controller sign` on the offline machine, copy the certificate
back in and run `webjetctl submit` on it.

Further controllers are ordinary enrolled containers whose node has the
`control` role (`--roles data,relay,control`, or `webjetctl node update` later);
they start the controller role by themselves. Runbook 4 continues from there.

Once the network runs, recreate the container without the key directory, so
account keys don't stay on the controller.

## Configuration

Without a configuration file, the entrypoint writes `webjetd.toml` from
environment variables:

| Variable | Default | `webjetd.toml` setting |
| --- | --- | --- |
| `WEBJET_ENROLL`, `WEBJET_ENROLL_FILE` | | Enrollment string for the first start. |
| `WEBJET_GENESIS` | | Path to a genesis: initialize the first controller. |
| `WEBJET_LISTEN_TLS` | `0.0.0.0:443` | `listen.tls` (`off` to disable). |
| `WEBJET_LISTEN_KCP` | `0.0.0.0:443` | `listen.kcp` (`off` to disable). |
| `WEBJET_LISTEN_ANYTLS` | | `listen.anytls`, e.g. `0.0.0.0:8443`. |
| `WEBJET_PUBLIC` | | `[[public]]`: comma-separated `transport:host:port`. |
| `WEBJET_TUN` | `true` | `tun.enabled`. |
| `WEBJET_TUN_NAME`, `WEBJET_MTU` | | `tun.name`, `tun.mtu`. |
| `WEBJET_GATEWAY_ROUTES` | | `[[gateway.route]]`: comma-separated `prefix[=interface]`. Without an interface, the one the prefix is directly connected to. |
| `WEBJET_CONTROLLER` | | `false` writes `controller.enabled = false`: never run the controller role, even with the `control` role. The role itself comes from the node's record. |
| `WEBJET_SIGNER_SOCKET` | | `controller.signer_socket`. |
| `WEBJET_HEAD_LIFETIME_HOURS` | | `controller.head_lifetime_hours`. |
| `WEBJET_METRICS_LISTEN` | | `metrics.listen`. |
| `WEBJET_KEY_STORAGE` | `auto` | `key.storage`. |
| `WEBJET_RELAY_CAPACITY_MBPS`, `WEBJET_RATE_CEILING_MBPS` | | `limits.*`. |
| `WEBJET_CONFIGURE_DNS` | `false` | `dns.configure_system`. |
| `WEBJET_LOG`, `WEBJET_LOG_FORMAT` | `info` | `log`, `log_format` (`json` for JSON lines). |

The file is regenerated on every start, so changing a variable and recreating
the container is enough.

For anything else, mount your own file at `/etc/webjet/webjetd.toml`; the
variables above are then ignored, except for the enrollment ones.

## Signing keys for controllers

Controllers sign tree heads. By default the key sits in the controller's
volume. To keep it in a separate process (§19.2), run `webjetd signer` in its
own container with no network, sharing only the socket:

```sh
docker volume create webjet-signer-run
docker run -d --name webjet-signer --network none \
  -v webjet-signer-key:/var/lib/webjet-signer \
  -v webjet-signer-run:/run/webjet-signer \
  -e WEBJET_SIGNER_SOCKET=/run/webjet-signer/signer.sock \
  webjet webjetd signer --socket /run/webjet-signer/signer.sock
# and on the controller:
#   -v webjet-signer-run:/run/webjet-signer
#   -e WEBJET_SIGNER_SOCKET=/run/webjet-signer/signer.sock
```

`docker/compose.example.yaml` puts a node, a controller and its signer
together.

## Identity key storage

The identity key is stored in the state volume. To seal it with the host's
TPM instead, pass the TPM in and ask for it:
`--device /dev/tpmrm0 -e WEBJET_KEY_STORAGE=tpm`. A sealed key can't be used
on another machine: moving the volume to a new host means re-keying the node.

## DNS

The agent answers DNS for the overlay's names on the network's resolver
address, through its tun interface: `resolver_ip` in the DNS configuration,
or by default the top address of the overlay pool (`webjetctl dns show`
prints the one in force). The examples below use 10.7.255.53.
It can't install split DNS from inside a container: that needs
systemd-resolved, which the image doesn't include. So `WEBJET_CONFIGURE_DNS`
is off by default, and the names are resolvable where the tun interface is:

- Processes in the agent's container, and containers that share its network
  namespace (`--network container:webjet`), reach the overlay and can query
  the resolver address directly, e.g. `dig @10.7.255.53 db-1.internal`.
- With `--network host`, the tun interface is the host's. Point the host's
  resolver at it once, for example on systemd-resolved hosts
  `resolvectl dns webjet0 10.7.255.53` and `resolvectl domain webjet0 '~internal'`.

## Health and logs

The image's health check runs `webjetctl status` against the agent, so
`docker ps` shows `healthy` once the agent answers. `docker logs` shows the
agent's log; set `WEBJET_LOG_FORMAT=json` for JSON lines.

Inspect a running node with `docker exec <name> webjetctl status`, `peers`,
`sessions` or `ping <node>`.

`docker stop` sends SIGTERM. The agent saves its state and exits, and the tun
interface and its routes go away with it. Allow it some time:
`--stop-timeout 30`.

## Upgrades

Pull or build the new image and recreate the container with the same volume.
Follow the release notes for the order (controllers one at a time, §20.6).

## Tests

`docker/deploy-test.sh` builds the image and runs the steps of this guide: a
first controller from a genesis, a node enrolled with `WEBJET_ENROLL`, a ping
across the overlay, a restart, a clean stop, and the error for a container
that isn't enrolled.
