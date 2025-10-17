
#pragma once

#include <stdio.h>
#include <time.h>
#include <stdarg.h>
#include <stdbool.h>

#include <pthread.h>
#define THREAD_LOCAL __thread

#define ANSI_RESET "\x1b[0m"
#define ANSI_RED "\x1b[31m"
#define ANSI_GREEN "\x1b[32m"
#define ANSI_CYAN "\x1b[36m"

#if SYSLOG
#include <syslog.h>
#endif

#if FILELOG
static const char *log_file_path = "epha.log";
static FILE *log_file;
#endif

static inline const char *now_local_iso8601();

static inline void logd_(const char *restrict func, const char *restrict fmt,
			 ...)
{
#if DEBUG
	va_list ap;
	va_start(ap, fmt);

	flockfile(stdout);
	fprintf(stdout, ANSI_CYAN);
	fprintf(stdout, "[D][%s] %s: ", now_local_iso8601(), func);
	vfprintf(stdout, fmt, ap);
	va_end(ap);
	fprintf(stdout, ANSI_RESET);
	fflush(stdout);
	funlockfile(stdout);
#else
	(void)func;
	(void)fmt;
#endif
}

void log_init()
{
#if SYSLOG
	const int options = LOG_CONS | LOG_NDELAY | LOG_PID;
	const int facility = LOG_USER;
	openlog(NULL, options, facility);
#endif
#if FILELOG
	log_file = fopen(log_file_path, "a");
	if (!log_file) {
		fprintf(stderr,
			"Cannot open file %s in order to init logger!\n",
			log_file_path);
		exit(EXIT_FAILURE);
	}
#endif
}

void log_close()
{
#if SYSLOG
	closelog();
#endif
#if FILELOG
	fflush(log_file);
	fclose(log_file);
#endif
}

static inline void log_(bool ERROR, const char *restrict func,
			const char *restrict fmt, ...)
{
#if FILELOG
	FILE *out_ = log_file;
#else
	FILE *out_ = ERROR ? stderr : stdout;
#endif
	va_list ap;
	va_start(ap, fmt);
#if SYSLOG
	va_list ap_syslog;
	va_copy(ap_syslog, ap);
#endif

	// LOCK
	flockfile(out_);

#if !FILELOG
	if (ERROR) {
		fprintf(out_, ANSI_RED);
	} else {
		fprintf(out_, ANSI_GREEN);
	}
#endif

	fprintf(out_, "[%c][%s] %s: ", ERROR ? 'E' : 'I', now_local_iso8601(),
		func);
	vfprintf(out_, fmt, ap);
	va_end(ap);

#if !FILELOG
	fprintf(out_, ANSI_RESET);
#endif

	fprintf(out_, "\n");

	// UNLOCK
	funlockfile(out_);

#if SYSLOG
	vsyslog(ERROR ? LOG_ERR : LOG_INFO, fmt, ap_syslog);
	va_end(ap_syslog);
#endif
}

#define LOG(fmt, ...) log_(false, __func__, fmt, ##__VA_ARGS__)
#define LOGE(fmt, ...) log_(true, __func__, fmt, ##__VA_ARGS__)
#define LOGD(fmt, ...) logd_(__func__, fmt, ##__VA_ARGS__)
