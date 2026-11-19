# SoftEther VPN for macOS (Apple Silicon)

A native menu-bar VPN client for macOS that speaks the SoftEther protocol,
with full tunnel, split tunnel (in both directions) and split DNS.

**Status: work in progress.** The C side is built and tested on Linux. The
Swift app and tunnel extension have not been compiled yet (see
[What is verified](#what-is-verified)).

## How it works

```
SoftEther VPN.app  (SwiftUI menu bar app)
   |  profile as JSON, password from the keychain
   v
Tunnel system extension : NEPacketTunnelProvider
   |  Bridge/se_bridge.h (plain C)
   v
SoftEther core (src/Mayaqua, src/Cedar), in-process client session
   |
   v
L3 TUN packet adapter (src/Cedar/VLanAndroid.c)
   ARP, DHCP and IPv6 neighbor discovery in user space,
   raw IP packets over a datagram socket pair  <->  NEPacketTunnelFlow
```

No kernel extension and no TAP driver. The tunnel is a standard
NetworkExtension packet tunnel, so macOS applies and removes routes and DNS
settings itself.

Because the tunnel is Layer 3, it carries IPv4 and IPv6 only. Bridging and
non-IP Ethernet protocols are not available on this client.

## Traffic and DNS modes

| Setting | Effect |
|---|---|
| All traffic | Default route through the VPN. |
| Only these networks | The VPN's own subnet, the listed networks, and (optionally) the routes the hub's DHCP server pushes. A pushed default route is ignored. |
| All traffic except these networks | Default route through the VPN, listed networks bypass it. |
| DNS: Automatic | All names via the VPN when everything is routed. With "Only these networks": only the hub's DHCP domain and the listed domains. |
| DNS: all names | The VPN's DNS servers resolve everything. |
| DNS: only these domains | Split DNS on the listed domains plus the hub's DHCP domain. |
| DNS: don't change | The system resolver is left alone. |

The decision logic is `Bridge/se_plan.c`. It is plain C with no dependency on
the core, and the Swift provider only maps its result onto
`NEPacketTunnelNetworkSettings`.

A SoftEther server can push one DHCP domain name and a list of routes, but not
a list of split-DNS domains. Additional domains have to be set in the profile.

## Layout

| Path | Contents |
|---|---|
| `CMakeLists.txt` | Build entry: core + bridge + tests. Configures on macOS and Linux. |
| `Bridge/se_bridge.{h,c}` | Session API: connect, status, IP configuration, packet descriptor, server certificate. |
| `Bridge/se_plan.{h,c}` | Routes and DNS plan from the profile and the hub's answer. |
| `Bridge/test/` | `se_plan_test` (unit), `se_bridge_test` + `run-linux-test.sh` (end to end against a local vpnserver). |
| `App/Shared/` | Profile model and Swift helpers over the bridge. |
| `App/Tunnel/` | Packet tunnel provider (system extension). |
| `App/App/` | Menu bar app: connections, editor, keychain, extension install. |
| `App/project.yml` | XcodeGen project definition. |
| `scripts/build-core.sh` | Builds the core and bridge for arm64 macOS. |

## Changes to the SoftEther core

Three files, all behind macros that only this folder's `CMakeLists.txt`
defines. The desktop and Android builds compile exactly as before.

- `src/Cedar/VLanAndroid.{c,h}`: also compiled when `SE_VLAN_L3_TUN` is
  defined. Adds `VLanAndroidGetDomainName` and `VLanAndroidGetClasslessRoutes`,
  and reports the machine's host name to DHCP on non-Android hosts.
- `src/Cedar/Session.c`: with `SE_CLIENT_CERT_PROMPT`, an unverified server
  certificate is handed to the client's check procedure instead of failing
  inside the TLS handshake (the behaviour the Windows client already has), so
  the app can show the fingerprint and offer to trust it.

## Building

On an Apple Silicon Mac with Xcode:

```bash
brew install cmake pkg-config openssl@3 libsodium xcodegen
```

```bash
SoftEtherVPN-macOS/scripts/build-core.sh
```

```bash
cd SoftEtherVPN-macOS/App && xcodegen generate && open SoftEtherVPN.xcodeproj
```

Then set your development team in `project.yml` (or in Xcode) and build the
`SoftEtherVPN` scheme. The app must be in `/Applications` for macOS to accept
the system extension.

Unless you are the SoftEther project, change the `org.softether.vpnclient.macos`
bundle identifiers and the product name. The Apache licence does not grant use
of the SoftEther name.

## Testing the C side

On Linux or macOS, with a normal desktop build of the repo in `build/`:

```bash
cmake -S SoftEtherVPN-macOS -B build-bridge && cmake --build build-bridge -j
```

```bash
build-bridge/se_plan_test
```

```bash
SoftEtherVPN-macOS/Bridge/test/run-linux-test.sh build build-bridge
```

The second script starts a throwaway vpnserver with one hub (SecureNAT, a DHCP
domain, one pushed route) and drives a real session through the bridge.

## What is verified

Verified on Linux x86-64 (gcc, OpenSSL 3.0):

- The desktop targets still build with the core changes, and `libcedar` from
  the desktop build contains none of the L3 adapter code.
- `se_plan_test`: 81 checks covering network parsing, full tunnel, both split
  tunnel directions, split DNS and the fallbacks. Clean under
  AddressSanitizer and UBSan.
- `run-linux-test.sh`: an unknown server certificate is refused and reported,
  a wrong password is reported as an authentication failure, a pinned
  certificate connects, the DHCP address, DNS server, domain name and pushed
  route arrive, and an ICMP echo written as a raw IPv4 packet is answered by
  the hub's gateway.

Not verified:

- Nothing has been compiled or run on macOS. That includes the core's
  `UNIX_MACOS` build with these changes, although upstream CI builds the
  unmodified core on arm64 macOS.
- The Swift sources and `project.yml` have never been through a compiler.
- Behaviour of the core inside the extension's sandbox. Known point to check:
  at start-up the core writes `lang.config` next to the executable
  (`Mayaqua/Table.c`), which is read-only inside a signed bundle.
- NetworkExtension behaviour of the generated settings (in particular split
  DNS with `matchDomains`) on a real system.
- IPv6 through the bridge.

## Open items

1. First build on a Mac; fix whatever the Swift compiler and Xcode report.
2. Bundle or statically link OpenSSL and libsodium. `libcedar` and
   `libmayaqua` currently link against Homebrew's dylibs by absolute path.
3. Developer ID signing, hardened runtime, notarization, installer.
4. Password for automatic reconnects after a reboot or on demand. Today the
   app passes it when the user connects, so only user-initiated connections
   can authenticate with a password.
5. Full tunnel on a hub without IPv6 leaves IPv6 traffic outside the VPN.
   Needs a block-IPv6 option.
6. Import of `.vpn` connection files exported by the Windows client.
7. Proxy settings in the editor (the bridge already supports them).
8. Seamless reconnect: reuse of the DHCP lease across reconnects, as the
   Android client does.
