# SoftEther VPN for macOS (Apple Silicon)

A native menu-bar VPN client for macOS that speaks the SoftEther protocol,
with full tunnel, split tunnel (in both directions) and split DNS.

**Status: not yet built on a Mac.** The C side is built and tested on Linux.
The Swift app and tunnel extension are complete in source but have not been
through a compiler (see [What is verified](#what-is-verified)).

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
| What the VPN server says (default) | Like the Windows client. IPv4: if the hub's DHCP server pushes routes (option 121), only the VPN's subnet and those routes are used and its default gateway is ignored (RFC 3442); a pushed default route means everything. With no pushed routes, a default gateway means everything; without one, only the VPN's subnet. IPv6, decided separately: everything if the hub advertises a router, else only the advertised prefix. |
| All traffic | Default route through the VPN. |
| Only these networks | The VPN's own subnet, the listed networks, and (optionally) the routes the hub's DHCP server pushes. A pushed default route is ignored. |
| All traffic except these networks | Default route through the VPN, listed networks bypass it. |
| DNS: Automatic | All names via the VPN when everything is routed. On a split tunnel: only the hub's DHCP domain and the listed domains. If neither exists, the Mac's own DNS stays in charge and the VPN's DNS server is not used; the app says so. |
| DNS: all names | The VPN's DNS servers resolve everything. |
| DNS: only these domains | Split DNS on the listed domains plus the hub's DHCP domain. |
| DNS: don't change | The system resolver is left alone. |
| Block IPv6 when the VPN has none | Whenever everything is routed through the VPN (also when the server decided so), IPv6 is captured and dropped so it cannot leave outside the VPN. On by default. |

The decision logic is `Bridge/se_plan.c`. It is plain C with no dependency on
the core, and the Swift provider only maps its result onto
`NEPacketTunnelNetworkSettings`.

To split-tunnel from the server, clear the default gateway of the Virtual DHCP
Server and set its pushed routes (`DhcpSet /GW:none /PUSHROUTE:...`); to send
everything through the VPN, set a default gateway and push no routes.

A SoftEther server can push one DHCP domain name and a list of routes, but not
a list of split-DNS domains. Additional domains have to be set in the profile.

## Several connections at once

Every profile has its own VPN configuration and its own tunnel interface, so
any number of them (up to `SE_MAX_SESSIONS`, 8) can be connected together. All
tunnels run in the one system extension process, each as its own provider
instance with its own SoftEther session.

macOS keeps the routes and DNS domains of each tunnel apart, so the natural
setup is one split-tunnel profile per network, each with its own DNS domains.
Two things cannot be shared, and the app warns about both:

- Only one connected profile can carry "all traffic". Where routes of two
  tunnels overlap, macOS uses one of them.
- Only one connected profile can resolve all names.

How a profile's own connection to its VPN server is routed while another
profile carries all traffic has not been tested.

## Layout

| Path | Contents |
|---|---|
| `CMakeLists.txt` | Build entry: core + bridge + tests. Configures on macOS and Linux. |
| `Bridge/se_bridge.{h,c}` | Session API: connect, status, IP configuration, packet descriptor, server certificate, `.vpn` import. |
| `Bridge/se_plan.{h,c}` | Routes and DNS plan from the profile and the hub's answer. |
| `Bridge/test/` | `se_plan_test` (unit), `se_bridge_test` + `run-e2e-test.sh` (end to end against a local vpnserver). |
| `App/Shared/` | Profile model and Swift helpers over the bridge. |
| `App/Tunnel/` | Packet tunnel provider (system extension). |
| `App/App/` | Menu bar app: connections, editor, keychain, extension install. |
| `App/project.yml` | XcodeGen project definition. |
| `scripts/build-core.sh` | Builds the core and bridge for arm64 macOS. |
| `scripts/bundle-deps.sh` | Build phase: copies OpenSSL and libsodium into the bundles. |
| `scripts/package.sh` | Signed, notarized disk image. |

## Changes to the SoftEther core

Three files. The behaviour changes sit behind macros that only this folder's
`CMakeLists.txt` defines, so the desktop builds compile to the same code as
before.

- `src/Cedar/VLanAndroid.{c,h}`: also compiled when `SE_VLAN_L3_TUN` is
  defined. Adds `VLanAndroidGetDomainName` and `VLanAndroidGetClasslessRoutes`
  and the field they read, and reports the machine's host name to DHCP on
  non-Android hosts. The Android build gets the new field and the two
  functions as well; nothing else changes for it.
- `src/Cedar/Session.c`:
  - `SE_CLIENT_CERT_PROMPT`: an unverified server certificate is handed to the
    client's check procedure instead of failing inside the TLS handshake (what
    the Windows client already does), so the app can show the fingerprint and
    offer to trust it. The check still runs before any credentials are sent.
  - `SE_CLIENT_SESSION_EXTRA_REF`: `NewClientSessionEx` takes a second session
    reference for its caller before the client thread starts. Taking it
    afterwards, as the Android bridge does, races with a session that fails
    at once.

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
`SoftEtherVPN` scheme. The app must be in `/Applications`: macOS refuses to
install a system extension from an app that runs from anywhere else.

Unless you are the SoftEther project, change the `org.softether.vpnclient.macos`
bundle identifiers and the product name. The Apache licence does not grant use
of the SoftEther name.

## Testing the C side

On Linux or macOS, with a normal desktop build of the repo in `build/`:

```bash
cmake -S SoftEtherVPN-macOS -B build-bridge -DCMAKE_BUILD_TYPE=Release && cmake --build build-bridge -j
```

```bash
build-bridge/se_plan_test
```

```bash
SoftEtherVPN-macOS/Bridge/test/run-e2e-test.sh build build-bridge
```

The second script starts a throwaway vpnserver with one hub (SecureNAT, a DHCP
domain, one pushed route) and drives a real session through the bridge.

## What is verified

Verified on Linux x86-64 (gcc, OpenSSL 3.0):

- The desktop targets still build with the core changes, and `libcedar` from
  the desktop build contains none of the L3 adapter code.
- `se_plan_test`: 159 checks covering network parsing, the server-decided
  mode, full tunnel, both split tunnel directions, split DNS, IPv6 leak
  protection, over-long and over-full lists, and domain validation. Clean
  under AddressSanitizer and UBSan.
- `run-e2e-test.sh`, against a real local vpnserver:
  - an unknown server certificate is refused and reported, and a pinned one
    connects;
  - a wrong password is reported as an authentication failure;
  - the DHCP address, DNS server, domain name and pushed route arrive;
  - an ICMP echo written as a raw IPv4 packet is answered by the hub's gateway;
  - the handle of an ended session stays invalid after later sessions start;
  - two sessions to two hubs run side by side with separate addresses, DNS
    domains and packet descriptors, without crosstalk; ending one leaves the
    other carrying traffic, and a refused certificate is reported for its own
    session only;
  - a `.vpn` file exported by the desktop vpnclient is imported, and the
    session logs in with the password hash it carries.
- That test is clean under AddressSanitizer, UBSan and LeakSanitizer. Under
  ThreadSanitizer it reports only unsynchronised reads of status flags, the
  pattern the core uses throughout.
- The same test passes as an unprivileged user with the program folder
  read-only, which is the situation inside a signed bundle.

Not verified:

- Nothing has been compiled or run on macOS. That includes the core's
  `UNIX_MACOS` build with these changes, although upstream CI builds the
  unmodified core on arm64 macOS.
- The Swift sources, `project.yml`, `bundle-deps.sh` and `package.sh` have
  never been run. The Swift code was reviewed twice by reading only.
- Behaviour inside the extension's App Sandbox, and what macOS does with the
  generated settings (in particular split DNS and on-demand connection).
- That a tunnel provider's own connection to its server bypasses the tunnel
  routes, which the full-tunnel modes rely on. This is how NetworkExtension
  packet tunnels are understood to work; it has not been observed here.
- Several tunnels of one app connected together. Other projects report that
  macOS supports this (for example WireGuard/wireguard-apple pull request 63,
  tested on macOS 26), but it has not been tried with this app.
- That Windows ignores the DHCP default gateway when routes are pushed. The
  server-decided mode follows RFC 3442 and SoftEther's documentation on this.
- IPv6 through the bridge (the test server's SecureNAT has no IPv6).

`.github/workflows/macos_client.yml` runs the build, the tests above and an
unsigned Xcode build on an Apple Silicon runner. It has not run yet; the first
run will show what needs fixing.

## Distribution

`scripts/package.sh <notarytool profile>` archives, exports with Developer ID
signing, notarizes, staples and produces a disk image. It needs a paid Apple
Developer account with:

- a Developer ID Application certificate;
- the Network Extension and System Extension capabilities on both bundle
  identifiers, with Developer ID provisioning profiles;
- `DEVELOPMENT_TEAM` set in `App/project.yml`.

`scripts/bundle-deps.sh` runs as a build phase and copies Homebrew's OpenSSL
and libsodium into each bundle. Homebrew builds those for the macOS version of
the build machine, so build on the oldest macOS you want to support, or link
static libraries built for the deployment target instead.

## Known limits

- Layer 3 only: no bridging, no non-IP protocols.
- Smart card sign-in is not supported.
- Where secrets are kept:
  - the password is in the login keychain;
  - a saved password hash from an imported `.vpn` file, a client private key
    and a proxy password are in the owner-only profiles file;
  - a profile that connects automatically also has all of these in its saved
    VPN configuration, which the system keeps outside the keychain, because
    the system starts that tunnel without the app. Profiles connected by hand
    are saved without them.
- With IPv6 blocked, IPv6 packets are dropped silently, so an application
  waits for its own timeout before it falls back to IPv4.
- A VPN configuration whose profile no longer exists in the app is stopped
  and removed automatically, at launch and whenever the list of profiles
  changes. The one exception: if the profiles file exists but cannot be read,
  nothing is removed, because the list of profiles is then unknown.
- A reconnect asks the hub's DHCP server again. The Android client's lease
  reuse (`VLanAndroidSetCachedIPv4`) would make reconnects faster, but it does
  not carry the DHCP domain name, which split DNS needs.
- The hub's DHCP domain is the only DNS domain a SoftEther server can
  announce. Further split-DNS domains have to be entered in the profile.
