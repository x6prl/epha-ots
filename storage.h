#pragma once

#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <ctype.h>

#include <pthread.h>

#define MAX_ID_LEN 32
#define DEFAULT_TTL_SEC 3600
#define BLOB_ID_HEX_LEN 32

static inline double now_s(void)
{
	struct timespec ts;
	clock_gettime(CLOCK_MONOTONIC, &ts);
	return (double)ts.tv_sec + (double)ts.tv_nsec * 1e-9;
}

static void secure_zero(void *p, size_t n)
{
	explicit_bzero(p, n);
}

struct blob_t {
	char id[MAX_ID_LEN + 1];
	uint8_t *data;
	size_t length;
	double expires_at;
	bool in_use;
};

enum BlobPutStatus {
	BLOB_PUT_OK = 0,
	BLOB_PUT_DUP,
	BLOB_PUT_FULL,
	BLOB_PUT_OOM
};

// Reserve space and copy payload into the in-memory blob store.
static enum BlobPutStatus blob_put(const char *id, const uint8_t *buf,
				   size_t len);

// Remove-and-return a blob by id; ownership transfers to caller.
static bool blob_take(const char *id, uint8_t **out_buf, size_t *out_len);

static struct {
	struct blob_t *items;
	int capacity;
	int in_use;
	int ttl_seconds;
	pthread_mutex_t mutex;
} blob_storage = { .items = NULL,
		   .capacity = 0,
		   .in_use = 0,
		   .ttl_seconds = DEFAULT_TTL_SEC,
		   .mutex = PTHREAD_MUTEX_INITIALIZER };

// Securely discard an entry; caller must hold blob_storage.mutex.
static void blob_free_locked(struct blob_t *b)
{
	if (!b || !b->in_use)
		return;
	if (b->data) {
		secure_zero(b->data, b->length);
		free(b->data);
	}
	secure_zero(b->id, sizeof(b->id));
	b->data = NULL;
	b->length = 0;
	b->expires_at = 0;
	b->in_use = false;
	if (blob_storage.in_use > 0)
		blob_storage.in_use--;
}

// Ensure blob id is canonical lowercase hex.
static bool id_valid(char *id)
{
	if (!id)
		return false;
	size_t len = strlen(id);
	if (len != BLOB_ID_HEX_LEN || len > MAX_ID_LEN)
		return false;
	for (size_t i = 0; i < len; i++) {
		unsigned char c = (unsigned char)id[i];
		if (!isxdigit(c))
			return false;
		id[i] = (char)tolower(c);
	}
	return true;
}
static enum BlobPutStatus blob_put(const char *id, const uint8_t *buf,
				   size_t len)
{
	if (!id || !buf)
		return BLOB_PUT_OOM;

	pthread_mutex_lock(&blob_storage.mutex);
	struct blob_t *slot = NULL;
	for (int i = 0; i < blob_storage.capacity; i++) {
		struct blob_t *b = &blob_storage.items[i];
		if (!b->in_use) {
			if (!slot)
				slot = b;
			continue;
		}
		if (strcmp(b->id, id) == 0) {
			pthread_mutex_unlock(&blob_storage.mutex);
			return BLOB_PUT_DUP;
		}
	}
	if (!slot) {
		pthread_mutex_unlock(&blob_storage.mutex);
		return BLOB_PUT_FULL;
	}

	// Copy payload into a new buffer owned by the store until retrieved.
	uint8_t *data = (uint8_t *)malloc(len);
	if (!data) {
		pthread_mutex_unlock(&blob_storage.mutex);
		return BLOB_PUT_OOM;
	}
	memcpy(data, buf, len);

	struct blob_t *b = slot;
	strncpy(b->id, id, sizeof(b->id) - 1);
	b->id[sizeof(b->id) - 1] = '\0';
	b->data = data;
	b->length = len;
	b->expires_at = now_s() + (blob_storage.ttl_seconds > 0 ?
					   blob_storage.ttl_seconds :
					   DEFAULT_TTL_SEC);
	b->in_use = true;
	blob_storage.in_use++;
	pthread_mutex_unlock(&blob_storage.mutex);

	return BLOB_PUT_OK;
}

static bool blob_take(const char *id, uint8_t **out_buf, size_t *out_len)
{
	if (!id || !out_buf)
		return false;
	bool ok = false;
	pthread_mutex_lock(&blob_storage.mutex);
	for (int i = 0; i < blob_storage.capacity; i++) {
		struct blob_t *b = &blob_storage.items[i];
		if (!b->in_use)
			continue;
		if (strcmp(b->id, id) != 0)
			continue;
		// Transfer ownership of the payload buffer to the caller.
		*out_buf = b->data;
		if (out_len)
			*out_len = b->length;
		b->data = NULL;
		b->length = 0;
		b->expires_at = 0;
		b->in_use = false;
		secure_zero(b->id, sizeof(b->id));
		if (blob_storage.in_use > 0)
			blob_storage.in_use--;
		ok = true;
		break;
	}
	pthread_mutex_unlock(&blob_storage.mutex);
	return ok;
}
