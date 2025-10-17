
#pragma once

#include <stdio.h>
#include <time.h>
#include <stdarg.h>
#include <stdbool.h>

#include <pthread.h>
#define THREAD_LOCAL __thread

#if SYSLOG
#include <syslog.h>
#endif

#if FILELOG
static const char *log_file_path = "epha.log";
static FILE *log_file;
#endif

static const char *now_local_iso8601();

static inline void logd_(const char *restrict func, const char *restrict fmt,
			 ...)
{
#if DEBUG
	va_list ap;
	va_start(ap, fmt);
	fprintf(stdout, "[D][%s] %s: ", now_local_iso8601(), func);
	vfprintf(stdout, fmt, ap);
	va_end(ap);
	fflush(stdout);
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
	fprintf(out_, "[%c][%s] %s: ", ERROR ? 'E' : 'I', now_local_iso8601(),
		func);
	vfprintf(out_, fmt, ap);
	va_end(ap);
	fprintf(out_, "\n");

#if SYSLOG
	va_start(ap, fmt);
	vsyslog(ERROR ? LOG_ERR : LOG_INFO, fmt, ap);
	va_end(ap);
#endif
}

#define LOG(fmt, ...) log_(false, __func__, fmt, ##__VA_ARGS__)
#define LOGE(fmt, ...) log_(true, __func__, fmt, ##__VA_ARGS__)
#define LOGD(fmt, ...) logd_(__func__, fmt, ##__VA_ARGS__)
