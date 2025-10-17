#pragma once

#include <time.h>
#include <stdio.h>
#include <microhttpd.h>

static inline const char *now_local_iso8601()
{
	static thread_local char buf[32];
	time_t t = time(NULL);
	struct tm tm;
	if (!localtime_r(&t, &tm))
		return NULL;
	if (strftime(buf, 32, "%Y-%m-%d %H:%M:%S %z", &tm) == 0)
		return NULL;
	size_t n = 0;
	while (buf[n])
		n++;
	if (n >= 5) { // ...HH:MM
		for (size_t i = n + 1; i-- > n - 1;)
			buf[i] = buf[i - 1];
		buf[n - 2] = ':';
	}
	return buf;
}

#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in.h>
#include <sys/socket.h>

static enum MHD_Result log_header_cb(void *cls, enum MHD_ValueKind kind,
				     const char *k, const char *v)
{
	(void)cls;
	(void)kind;
	LOG("H  %s: %s\n", k ? k : "", v ? v : "");
	return MHD_YES;
}
static enum MHD_Result log_cookie_cb(void *cls, enum MHD_ValueKind kind,
				     const char *k, const char *v)
{
	(void)cls;
	(void)kind;
	LOG("CK %s=%s\n", k ? k : "", v ? v : "");
	return MHD_YES;
}
static enum MHD_Result log_query_cb(void *cls, enum MHD_ValueKind kind,
				    const char *k, const char *v)
{
	(void)cls;
	(void)kind;
	LOG("Q  %s=%s\n", k ? k : "", v ? v : "");
	return MHD_YES;
}
static void log_client_addr(const struct sockaddr *sa)
{
	if (!sa) {
		LOG("Client: (unknown)\n");
		return;
	}
	char host[NI_MAXHOST] = "";
	uint16_t port = 0;
	if (sa->sa_family == AF_INET) {
		const struct sockaddr_in *in = (const struct sockaddr_in *)sa;
		inet_ntop(AF_INET, &in->sin_addr, host, sizeof(host));
		port = ntohs(in->sin_port);
	} else if (sa->sa_family == AF_INET6) {
		const struct sockaddr_in6 *in6 =
			(const struct sockaddr_in6 *)sa;
		inet_ntop(AF_INET6, &in6->sin6_addr, host, sizeof(host));
		port = ntohs(in6->sin6_port);
	}
	LOG("Client: %s:%u\n", host[0] ? host : "(unprintable)",
	    (unsigned)port);
}
