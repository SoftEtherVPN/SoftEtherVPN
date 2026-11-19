// SoftEther VPN for macOS - plain-C bridge to the SoftEther core
//
// This header is the whole surface the Swift side (packet tunnel provider and
// app) sees. It deliberately includes no Mayaqua / Cedar header: those define
// types and macros (UINT, bool, Lock, Free, Zero, ...) that collide with Apple
// SDK headers, so the core stays behind this boundary.
//
// Threading: every function may be called from any thread. Up to
// SE_MAX_SESSIONS sessions run side by side, each with its own handle and
// packet descriptor; a handle that was disconnected is rejected safely.

#ifndef SE_BRIDGE_H
#define SE_BRIDGE_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct se_session se_session;

// Concurrent sessions per process (one per connected profile)
#define SE_MAX_SESSIONS		8

// Authentication methods
enum
{
	SE_AUTH_ANONYMOUS = 0,
	SE_AUTH_PASSWORD = 1,		// SoftEther password authentication (hashed on the client)
	SE_AUTH_PLAIN_PASSWORD = 2,	// RADIUS / NT domain / LDAP (password sent inside TLS)
	SE_AUTH_CERT = 3,			// Client certificate
};

// Proxy types
enum
{
	SE_PROXY_DIRECT = 0,
	SE_PROXY_HTTP = 1,
	SE_PROXY_SOCKS4 = 2,
	SE_PROXY_SOCKS5 = 3,
};

// Session state
enum
{
	SE_STATUS_CONNECTING = 0,	// connecting, authenticating or waiting for DHCP / RA
	SE_STATUS_CONNECTED = 1,	// session up and IP configuration available
	SE_STATUS_CONFIG_ERROR = 2,	// session up but no IP configuration could be obtained
	SE_STATUS_DISCONNECTED = 3,	// session ended (see se_get_error)
};

// SoftEther error codes the UI treats specially (values from Cedar/Cedar.h)
enum
{
	SE_ERR_NO_ERROR = 0,
	SE_ERR_CONNECT_FAILED = 1,
	SE_ERR_HUB_NOT_FOUND = 8,
	SE_ERR_AUTH_FAILED = 9,
	SE_ERR_SERVER_CERT_EXPIRES = 106,
	SE_ERR_CERT_NOT_TRUSTED = 85,
	SE_ERR_HOSTNAME_MISMATCH = 149,
};

// Connection profile. All strings are UTF-8 and may be NULL where noted; the
// bridge copies everything it needs before se_connect returns.
typedef struct
{
	const char *host;				// VPN server host name or address (required)
	uint16_t port;					// 0 = 443
	const char *hub;				// Virtual Hub name (required)

	int auth_type;					// SE_AUTH_*
	const char *username;			// NULL for anonymous
	const char *password;			// SE_AUTH_PASSWORD / SE_AUTH_PLAIN_PASSWORD
	const uint8_t *password_hash;	// SE_AUTH_PASSWORD only: the 20-byte SoftEther password
									// hash, used instead of password when not NULL (this
									// is what an imported .vpn file carries)
	const uint8_t *client_cert;		// SE_AUTH_CERT: X.509, DER or PEM
	size_t client_cert_len;
	const uint8_t *client_key;		// SE_AUTH_CERT: private key, DER or PEM (unencrypted)
	size_t client_key_len;

	// Server certificate policy. With verify_server_cert the connection is
	// refused unless the server certificate chains to a trusted CA (those added
	// with se_add_trusted_ca, plus the OpenSSL default store when
	// use_default_trust is set) or is byte-identical to pinned_server_cert.
	// On refusal the offered certificate can be read with
	// se_get_offered_server_cert so the UI can ask the user and pin it.
	int verify_server_cert;
	int use_default_trust;
	const uint8_t *pinned_server_cert;	// DER or PEM, may be NULL
	size_t pinned_server_cert_len;

	int use_ipv4;					// DHCP over the hub
	int use_ipv6;					// router advertisement / SLAAC over the hub

	const uint8_t *mac_address;		// 6 bytes, or NULL for a random MAC per connect.
									// A stable MAC keeps the hub's DHCP lease.

	int max_connections;			// TCP connections of the session, 0 = 1
	int use_compress;
	int disable_udp_acceleration;

	int proxy_type;					// SE_PROXY_*
	const char *proxy_host;
	uint16_t proxy_port;
	const char *proxy_username;
	const char *proxy_password;
} se_profile;

#define SE_ADDR_LEN			64
#define SE_DOMAIN_LEN		256
#define SE_MAX_ROUTES		64

typedef struct
{
	char network[SE_ADDR_LEN];
	int prefix_len;
	char gateway[SE_ADDR_LEN];
} se_route;

// IPv4 configuration the hub handed out (DHCP). Empty strings where unset.
typedef struct
{
	char address[SE_ADDR_LEN];
	char mask[SE_ADDR_LEN];
	char gateway[SE_ADDR_LEN];
	char dns1[SE_ADDR_LEN];
	char dns2[SE_ADDR_LEN];
	char domain[SE_DOMAIN_LEN];		// DHCP option 15
	int num_routes;					// DHCP option 121 (classless static routes)
	se_route routes[SE_MAX_ROUTES];
} se_ipv4_config;

// IPv6 configuration learned from the hub's router advertisement
typedef struct
{
	char address[SE_ADDR_LEN];		// empty if the hub advertised no usable prefix
	int prefix_len;
	char router[SE_ADDR_LEN];
	char prefix[SE_ADDR_LEN];
	char dns[SE_ADDR_LEN];
} se_ipv6_config;

typedef struct
{
	uint64_t bytes_sent;
	uint64_t bytes_received;
} se_traffic;

#define SE_NAME_LEN			256
#define SE_SECRET_LEN		256
#define SE_PASSWORD_HASH_LEN	20
#define SE_BLOB_LEN			8192

// A connection setting read from a .vpn file exported by the SoftEther VPN
// Client (Windows "Export VPN Connection Setting", or vpncmd AccountExport)
typedef struct
{
	char name[SE_NAME_LEN];
	char host[SE_NAME_LEN];
	int port;
	char hub[SE_NAME_LEN];

	int auth_type;					// SE_AUTH_*; -1 for a method this client lacks
									// (smart card / OpenSSL engine)
	char username[SE_NAME_LEN];
	int has_password_hash;			// SE_AUTH_PASSWORD with a saved password
	uint8_t password_hash[SE_PASSWORD_HASH_LEN];
	char plain_password[SE_SECRET_LEN];	// SE_AUTH_PLAIN_PASSWORD with a saved password
	size_t client_cert_len;			// SE_AUTH_CERT: DER
	uint8_t client_cert[SE_BLOB_LEN];
	size_t client_key_len;			// SE_AUTH_CERT: DER
	uint8_t client_key[SE_BLOB_LEN];

	int verify_server_cert;
	int use_default_trust;
	size_t server_cert_len;			// pinned server certificate, DER
	uint8_t server_cert[SE_BLOB_LEN];

	int max_connections;
	int use_compress;
	int disable_udp_acceleration;

	int proxy_type;					// SE_PROXY_*
	char proxy_host[SE_NAME_LEN];
	int proxy_port;
	char proxy_username[SE_NAME_LEN];
	char proxy_password[SE_SECRET_LEN];
} se_imported_profile;

// Parse the contents of a .vpn file. Needs se_init. Returns 1 on success, 0
// with a message otherwise. The result holds secrets: wipe it after use.
int se_import_vpn_file(const uint8_t *data, size_t len, se_imported_profile *out,
	char *err, size_t err_size);

// Start the core. hamcore_path is the full path of hamcore.se2 (inside the
// bundle); temp_dir is a writable directory or NULL. Returns 1 on success.
// Safe to call more than once.
int se_init(const char *hamcore_path, const char *temp_dir);
void se_shutdown(void);

// "major.minor.build" of the SoftEther core
void se_core_version(char *dst, size_t dst_size);

// Add one trusted CA certificate (DER or PEM), e.g. from the system keychain
int se_add_trusted_ca(const uint8_t *cert, size_t len);

// Start a session. Returns NULL (and a message in err) if the profile is not
// usable or SE_MAX_SESSIONS are already running; otherwise the session is
// connecting in the background and se_get_status reports its progress.
se_session *se_connect(const se_profile *profile, char *err, size_t err_size);

// Stop the session and release it. The packet descriptor is closed here, so
// stop reading from it first. Idempotent for a stale handle.
void se_disconnect(se_session *s);

// Datagram descriptor that carries the session's IP packets: one read() or
// write() is exactly one raw IPv4 / IPv6 packet, without any header. Owned by
// the bridge. Returns -1 for a stale handle.
int se_packet_fd(se_session *s);

int se_get_status(se_session *s);
// SoftEther error code of the session (0 = none); meaningful once disconnected
int se_get_error(se_session *s);
// Human-readable state / error for the UI
void se_get_status_text(se_session *s, char *dst, size_t dst_size);

// Each returns 1 and fills *out when that configuration is available
int se_get_ipv4_config(se_session *s, se_ipv4_config *out);
int se_get_ipv6_config(se_session *s, se_ipv6_config *out);

// Address the session is actually connected to (after DNS resolution), for
// the tunnel's "remote address". Returns 1 when known.
int se_get_server_address(se_session *s, char *dst, size_t dst_size);

int se_get_traffic(se_session *s, se_traffic *out);

// The certificate the server offered when this session's connection attempt
// was refused for an untrusted / mismatching / expired certificate. Returns the
// DER length (0 if none) and copies up to buf_size bytes; sha256 receives the
// 32-byte fingerprint when not NULL. Read it before se_disconnect.
size_t se_get_offered_server_cert(se_session *s, uint8_t *buf, size_t buf_size, uint8_t *sha256);

#ifdef __cplusplus
}
#endif

#endif	// SE_BRIDGE_H
