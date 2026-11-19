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
static int WaitStatus(se_session *s, int timeout_sec)
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

static int Ping(se_session *s, const char *src, const char *dst)
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
	se_session *s;
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
		CHECK(se_connect(&bad, err, sizeof(err)) == NULL && err[0] != 0, "empty hub rejected: %s", err);
	}

	// 1. Unknown server certificate is refused
	printf("[1] verification on, nothing trusted\n");
	p.verify_server_cert = 1;
	s = se_connect(&p, err, sizeof(err));
	CHECK(s != NULL, "session started %s", err);
	st = WaitStatus(s, 30);
	CHECK(st == SE_STATUS_DISCONNECTED, "refused (status %d)", st);
	CHECK(se_get_error(s) == SE_ERR_CERT_NOT_TRUSTED, "error is CERT_NOT_TRUSTED (got %d)", se_get_error(s));
	cert_len = se_get_offered_server_cert(cert, sizeof(cert), fp);
	CHECK(cert_len > 0 && cert_len <= sizeof(cert), "offered certificate reported (%u bytes)", (unsigned)cert_len);
	printf("        sha256 ");
	for (i = 0; i < 32; i++)
	{
		printf("%02x", fp[i]);
	}
	printf("\n");
	se_disconnect(s);
	CHECK(se_get_status(s) == SE_STATUS_DISCONNECTED && se_packet_fd(s) == -1, "stale handle is rejected safely");

	// Wrong password with the certificate pinned
	printf("[2] pinned certificate, wrong password\n");
	p.pinned_server_cert = cert;
	p.pinned_server_cert_len = cert_len;
	p.password = "definitely-wrong";
	s = se_connect(&p, err, sizeof(err));
	CHECK(s != NULL, "session started %s", err);
	st = WaitStatus(s, 30);
	CHECK(st == SE_STATUS_DISCONNECTED && se_get_error(s) == SE_ERR_AUTH_FAILED,
		"authentication failure reported (status %d, error %d)", st, se_get_error(s));
	se_disconnect(s);
	p.password = argv[6];

	// 2..4. Pinned certificate connects, DHCP answer, ping
	printf("[3] pinned certificate, correct password\n");
	s = se_connect(&p, err, sizeof(err));
	CHECK(s != NULL, "session started %s", err);
	CHECK(se_connect(&p, err, sizeof(err)) == NULL, "second concurrent session rejected: %s", err);
	st = WaitStatus(s, 60);
	CHECK(st == SE_STATUS_CONNECTED, "connected (status %d)", st);

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

	se_shutdown();

	printf("%s (%d failure%s)\n", g_failed == 0 ? "PASSED" : "FAILED", g_failed, g_failed == 1 ? "" : "s");

	return g_failed == 0 ? 0 : 1;
}
