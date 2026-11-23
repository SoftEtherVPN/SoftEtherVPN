// End-to-end test of the bridge against a real SoftEther VPN Server.
//
//   se_bridge_test <hamcore.se2> <host> <port> <hub> <user> <password>
//
// Checks, in order:
//   1. a dial with server certificate verification is refused for an unknown
//      certificate, and the offered certificate is reported;
//   2. the same dial with that certificate pinned connects;
//   3. the hub's DHCP answer (address, gateway, DNS, domain, pushed routes)
//      is reported;
//   4. an ICMP echo written to the packet descriptor as a raw IPv4 packet is
//      answered by the gateway - i.e. the L3 <-> L2 conversion works both ways.
//
// Includes nothing but se_bridge.h, exactly like the Swift side.

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <poll.h>
#include <arpa/inet.h>

#include "se_bridge.h"

static int g_failed = 0;

#define CHECK(cond, ...) \
	do { if (cond) { printf("  ok    "); } else { printf("  FAIL  "); g_failed++; } \
	printf(__VA_ARGS__); printf("\n"); } while (0)

static unsigned short Checksum(const unsigned char *p, int len)
{
	unsigned long sum = 0;
	int i;

	for (i = 0; i + 1 < len; i += 2)
	{
		sum += (p[i] << 8) | p[i + 1];
	}
	if (len & 1)
	{
		sum += p[len - 1] << 8;
	}
	while (sum >> 16)
	{
		sum = (sum & 0xFFFF) + (sum >> 16);
	}

	return (unsigned short)~sum;
}

// Wait until the session leaves the connecting state
static int WaitStatus(se_session s, int timeout_sec)
{
	int i, st = SE_STATUS_CONNECTING;
	char last[512] = "", text[512];

	for (i = 0; i < timeout_sec * 10; i++)
	{
		st = se_get_status(s);

		se_get_status_text(s, text, sizeof(text));
		if (strcmp(text, last) != 0)
		{
			printf("        status: %s\n", text);
			strcpy(last, text);
		}

		if (st != SE_STATUS_CONNECTING)
		{
			break;
		}

		usleep(100 * 1000);
	}

	return st;
}

static int Ping(se_session s, const char *src, const char *dst)
{
	unsigned char pkt[28 + 32];
	unsigned char buf[2048];
	unsigned short c;
	int fd = se_packet_fd(s);
	int tries, n;
	struct in_addr a_src, a_dst;

	if (fd < 0 || inet_pton(AF_INET, src, &a_src) != 1 || inet_pton(AF_INET, dst, &a_dst) != 1)
	{
		return 0;
	}

	for (tries = 0; tries < 5; tries++)
	{
		struct pollfd pfd;
		int waited;

		memset(pkt, 0, sizeof(pkt));

		// IPv4 header
		pkt[0] = 0x45;
		pkt[2] = (unsigned char)(sizeof(pkt) >> 8);
		pkt[3] = (unsigned char)(sizeof(pkt) & 0xFF);
		pkt[8] = 64;
		pkt[9] = 1;	// ICMP
		memcpy(pkt + 12, &a_src, 4);
		memcpy(pkt + 16, &a_dst, 4);
		c = Checksum(pkt, 20);
		pkt[10] = (unsigned char)(c >> 8);
		pkt[11] = (unsigned char)(c & 0xFF);

		// ICMP echo request
		pkt[20] = 8;
		pkt[24] = 0x53;
		pkt[25] = 0x45;
		pkt[27] = (unsigned char)(tries + 1);
		memset(pkt + 28, 0xA5, 32);
		c = Checksum(pkt + 20, sizeof(pkt) - 20);
		pkt[22] = (unsigned char)(c >> 8);
		pkt[23] = (unsigned char)(c & 0xFF);

		if (write(fd, pkt, sizeof(pkt)) != (ssize_t)sizeof(pkt))
		{
			return 0;
		}

		for (waited = 0; waited < 1000; waited += 100)
		{
			pfd.fd = fd;
			pfd.events = POLLIN;
			pfd.revents = 0;

			if (poll(&pfd, 1, 100) <= 0)
			{
				continue;
			}

			n = (int)read(fd, buf, sizeof(buf));

			// Echo reply from dst to src carrying our identifier
			if (n >= 28 && (buf[0] >> 4) == 4 && buf[9] == 1 &&
				memcmp(buf + 12, &a_dst, 4) == 0 && memcmp(buf + 16, &a_src, 4) == 0 &&
				buf[20] == 0 && buf[24] == 0x53 && buf[25] == 0x45)
			{
				return 1;
			}
		}
	}

	return 0;
}

int main(int argc, char *argv[])
{
	se_profile p;
	se_session s, stale = 0;
	char err[256], text[512], ver[64], addr[SE_ADDR_LEN];
	unsigned char cert[8192], fp[32];
	size_t cert_len;
	se_ipv4_config c4;
	se_traffic tr;
	int st, i;

	if (argc < 7)
	{
		fprintf(stderr, "usage: %s <hamcore.se2> <host> <port> <hub> <user> <password>\n", argv[0]);

		return 2;
	}

	CHECK(se_init(argv[1], NULL) == 1, "core initialized");
	se_core_version(ver, sizeof(ver));
	CHECK(ver[0] != 0, "core version %s", ver);

	memset(&p, 0, sizeof(p));
	p.host = argv[2];
	p.port = (uint16_t)atoi(argv[3]);
	p.hub = argv[4];
	p.auth_type = SE_AUTH_PASSWORD;
	p.username = argv[5];
	p.password = argv[6];
	p.use_ipv4 = 1;
	p.disable_udp_acceleration = 1;

	// Profile validation
	{
		se_profile bad = p;

		bad.hub = "";
		CHECK(se_connect(&bad, err, sizeof(err)) == 0 && err[0] != 0, "empty hub rejected: %s", err);
	}

	// 1. Unknown server certificate is refused
	printf("[1] verification on, nothing trusted\n");
	p.verify_server_cert = 1;
	s = se_connect(&p, err, sizeof(err));
	CHECK(s != 0, "session started %s", err);
	st = WaitStatus(s, 30);
	CHECK(st == SE_STATUS_DISCONNECTED, "refused (status %d)", st);
	CHECK(se_get_error(s) == SE_ERR_CERT_NOT_TRUSTED, "error is CERT_NOT_TRUSTED (got %d)", se_get_error(s));
	cert_len = se_get_offered_server_cert(s, cert, sizeof(cert), fp);
	CHECK(cert_len > 0 && cert_len <= sizeof(cert), "offered certificate reported (%u bytes)", (unsigned)cert_len);
	printf("        sha256 ");
	for (i = 0; i < 32; i++)
	{
		printf("%02x", fp[i]);
	}
	printf("\n");
	se_disconnect(s);
	CHECK(se_get_status(s) == SE_STATUS_DISCONNECTED && se_packet_fd(s) == -1, "stale handle is rejected safely");
	stale = s;

	// Wrong password with the certificate pinned
	printf("[2] pinned certificate, wrong password\n");
	p.pinned_server_cert = cert;
	p.pinned_server_cert_len = cert_len;
	p.password = "definitely-wrong";
	s = se_connect(&p, err, sizeof(err));
	CHECK(s != 0, "session started %s", err);
	st = WaitStatus(s, 30);
	CHECK(st == SE_STATUS_DISCONNECTED && se_get_error(s) == SE_ERR_AUTH_FAILED,
		"authentication failure reported (status %d, error %d)", st, se_get_error(s));
	se_disconnect(s);
	p.password = argv[6];

	// 2..4. Pinned certificate connects, DHCP answer, ping
	printf("[3] pinned certificate, correct password\n");
	s = se_connect(&p, err, sizeof(err));
	CHECK(s != 0, "session started %s", err);
	st = WaitStatus(s, 60);
	CHECK(st == SE_STATUS_CONNECTED, "connected (status %d)", st);

	// A handle is never reused: the one of the first, long ended session must
	// not have come to mean this one
	CHECK(s != stale && se_get_status(stale) == SE_STATUS_DISCONNECTED && se_packet_fd(stale) == -1,
		"the handle of an ended session stays invalid");
	se_disconnect(stale);
	CHECK(se_get_status(s) == SE_STATUS_CONNECTED, "disconnecting it again does not touch the live session");

	if (st == SE_STATUS_CONNECTED)
	{
		CHECK(se_get_ipv4_config(s, &c4) == 1, "IPv4 configuration available");
		printf("        address %s mask %s gateway %s\n", c4.address, c4.mask, c4.gateway);
		printf("        dns %s %s domain '%s' pushed routes %d\n", c4.dns1, c4.dns2, c4.domain, c4.num_routes);
		for (i = 0; i < c4.num_routes; i++)
		{
			printf("        route %s/%d via %s\n", c4.routes[i].network, c4.routes[i].prefix_len, c4.routes[i].gateway);
		}
		CHECK(c4.address[0] != 0 && c4.mask[0] != 0, "address and mask set");

		if (getenv("SE_TEST_EXPECT_DOMAIN") != NULL)
		{
			CHECK(strcmp(c4.domain, getenv("SE_TEST_EXPECT_DOMAIN")) == 0, "DHCP domain name is '%s'", c4.domain);
		}
		if (getenv("SE_TEST_EXPECT_ROUTES") != NULL)
		{
			CHECK(c4.num_routes == atoi(getenv("SE_TEST_EXPECT_ROUTES")), "%d pushed route(s)", c4.num_routes);
		}

		CHECK(se_get_server_address(s, addr, sizeof(addr)) == 1, "server address %s", addr);

		if (c4.gateway[0] != 0)
		{
			CHECK(Ping(s, c4.address, c4.gateway) == 1, "ICMP echo to gateway %s answered through the packet descriptor", c4.gateway);
		}

		CHECK(se_get_traffic(s, &tr) == 1 && tr.bytes_sent > 0 && tr.bytes_received > 0,
			"traffic counters %llu sent / %llu received",
			(unsigned long long)tr.bytes_sent, (unsigned long long)tr.bytes_received);
	}

	se_disconnect(s);
	se_get_status_text(s, text, sizeof(text));
	CHECK(strcmp(text, "Disconnected.") == 0, "disconnected cleanly");

	// Several connections at once: a second hub with its own address range and
	// DNS domain, connected while the first is up. Each session has its own
	// packet descriptor and configuration, and ending one leaves the other alone.
	if (getenv("SE_TEST_HUB2") != NULL)
	{
		se_session s1, s2;
		se_profile p2 = p;
		se_ipv4_config a, b;
		unsigned char mac1[6] = { 0x02, 0x11, 0x22, 0x33, 0x44, 0x01 };
		unsigned char mac2[6] = { 0x02, 0x11, 0x22, 0x33, 0x44, 0x02 };

		printf("[multi] two connections at the same time\n");

		p.mac_address = mac1;
		p2.mac_address = mac2;
		p2.hub = getenv("SE_TEST_HUB2");

		s1 = se_connect(&p, err, sizeof(err));
		CHECK(s1 != 0, "first session started %s", err);
		s2 = se_connect(&p2, err, sizeof(err));
		CHECK(s2 != 0 && s2 != s1, "second session started alongside %s", err);

		CHECK(WaitStatus(s1, 60) == SE_STATUS_CONNECTED, "first connected");
		CHECK(WaitStatus(s2, 60) == SE_STATUS_CONNECTED, "second connected");

		memset(&a, 0, sizeof(a));
		memset(&b, 0, sizeof(b));
		CHECK(se_get_ipv4_config(s1, &a) == 1 && se_get_ipv4_config(s2, &b) == 1, "both have a configuration");
		printf("        first  %s domain '%s'\n        second %s domain '%s'\n", a.address, a.domain, b.address, b.domain);
		CHECK(strcmp(a.gateway, b.gateway) != 0 && strcmp(a.domain, b.domain) != 0,
			"each session reports its own hub's network and domain");
		CHECK(se_packet_fd(s1) >= 0 && se_packet_fd(s2) >= 0 && se_packet_fd(s1) != se_packet_fd(s2),
			"separate packet descriptors");

		CHECK(Ping(s1, a.address, a.gateway) == 1, "first hub's gateway %s answers on the first descriptor", a.gateway);
		CHECK(Ping(s2, b.address, b.gateway) == 1, "second hub's gateway %s answers on the second descriptor", b.gateway);
		// No crosstalk: the first hub's gateway is not reachable through the second session
		CHECK(Ping(s2, b.address, a.gateway) == 0, "the second session does not reach the first hub");

		se_disconnect(s1);
		CHECK(se_get_status(s1) == SE_STATUS_DISCONNECTED && se_get_status(s2) == SE_STATUS_CONNECTED,
			"ending the first leaves the second connected");
		CHECK(Ping(s2, b.address, b.gateway) == 1, "the second still carries traffic");

		// A refused certificate is reported per session
		{
			se_profile p3 = p;
			se_session s3;
			unsigned char c3[8192];

			p3.pinned_server_cert = NULL;
			p3.pinned_server_cert_len = 0;
			s3 = se_connect(&p3, err, sizeof(err));
			CHECK(s3 != 0 && WaitStatus(s3, 30) == SE_STATUS_DISCONNECTED, "third session refused for its certificate");
			CHECK(se_get_offered_server_cert(s3, c3, sizeof(c3), NULL) == cert_len &&
				se_get_offered_server_cert(s2, c3, sizeof(c3), NULL) == 0,
				"the offered certificate belongs to the refused session only");
			se_disconnect(s3);
		}

		CHECK(se_get_status(s2) == SE_STATUS_CONNECTED, "the second is unaffected");
		se_disconnect(s2);

		p.mac_address = NULL;
	}

	// 5. A .vpn file exported by the desktop client: import it, and log in
	//    with the password hash it carries
	if (getenv("SE_TEST_VPN_FILE") != NULL)
	{
		static se_imported_profile imp;
		static unsigned char file[65536];
		FILE *f = fopen(getenv("SE_TEST_VPN_FILE"), "rb");
		size_t n = (f != NULL) ? fread(file, 1, sizeof(file), f) : 0;

		if (f != NULL)
		{
			fclose(f);
		}

		printf("[4] imported .vpn file\n");
		CHECK(n > 0, ".vpn file read (%u bytes)", (unsigned)n);
		CHECK(se_import_vpn_file(file, n, &imp, err, sizeof(err)) == 1, "parsed %s", err);
		printf("        name '%s' host %s port %d hub %s user %s auth %d\n",
			imp.name, imp.host, imp.port, imp.hub, imp.username, imp.auth_type);
		CHECK(strcmp(imp.name, "Office VPN") == 0 && strcmp(imp.host, argv[2]) == 0 &&
			imp.port == atoi(argv[3]) && strcmp(imp.hub, argv[4]) == 0 &&
			strcmp(imp.username, argv[5]) == 0, "name, server, port, hub and user match");
		CHECK(imp.auth_type == SE_AUTH_PASSWORD && imp.has_password_hash == 1, "saved password hash present");
		CHECK(se_import_vpn_file((const uint8_t *)"not a vpn file", 14, &imp, err, sizeof(err)) == 0 && err[0] != 0,
			"garbage rejected: %s", err);

		CHECK(se_import_vpn_file(file, n, &imp, err, sizeof(err)) == 1, "parsed again");
		p.host = imp.host;
		p.port = (uint16_t)imp.port;
		p.hub = imp.hub;
		p.username = imp.username;
		p.password = NULL;
		p.password_hash = imp.password_hash;

		s = se_connect(&p, err, sizeof(err));
		CHECK(s != 0, "session started %s", err);
		st = WaitStatus(s, 60);
		CHECK(st == SE_STATUS_CONNECTED, "connected with the imported credentials (status %d)", st);
		se_disconnect(s);
	}

	se_shutdown();

	printf("%s (%d failure%s)\n", g_failed == 0 ? "PASSED" : "FAILED", g_failed, g_failed == 1 ? "" : "s");

	return g_failed == 0 ? 0 : 1;
}
