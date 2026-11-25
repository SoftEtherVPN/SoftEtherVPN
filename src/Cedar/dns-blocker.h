// SoftEther VPN Source Code - Developer Edition Master Branch
// Cedar Communication Module


// dns-blocker.h
// DNS leak blocker for Win32 VPN client sessions

#ifdef OS_WIN32

#ifndef DNSBLOCKER_H
#define DNSBLOCKER_H

#ifdef __cplusplus
class DnsBlockerPrivate;
class DnsBlocker
{
public:
	DnsBlocker();
	~DnsBlocker();

	void prepare();

	void start();
	void stop();

	bool isFilterable() const;

private:
	unsigned int applyFilters(void *wfpEngine);

	int forceStaticDns();
	int useDhcp();

private:
	// Disables copy.
	DnsBlocker(const DnsBlocker &);
	DnsBlocker &operator=(const DnsBlocker &);

	DnsBlockerPrivate *d;
};

extern "C" {
#endif // __cplusplus

void *NewDnsBlocker();
void FreeDnsBlocker(void *blocker);
void PrepareDnsBlocker(void *blocker);
void StartDnsBlocker(void *blocker);
void StopDnsBlocker(void *blocker);

#ifdef __cplusplus
} // extern "C"
#endif // __cplusplus

#endif // DNSBLOCKER_H

#endif // OS_WIN32
