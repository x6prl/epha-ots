/*
 * Copyright (C) 2025 adnihilum authors
 *
 * This file is part of adnihilum.
 *
 * adnihilum is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * adnihilum is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with adnihilum.  If not, see <https://www.gnu.org/licenses/>.
 */
// SPDX-License-Identifier: GPL-3.0-or-later

#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <assert.h>

#include "../log.h"
#include "../types.h"

// ------------------------------------------------------------
// MOCK
// ------------------------------------------------------------

#define TABLE_SIZE 16u
static htable_key_t g_keys[TABLE_SIZE];
static int g_vals[TABLE_SIZE];

static bool key_is_null(htable_key_t a)
{
	return (a.h == 0 && a.l == 0);
}

static void key_set_null(htable_key_t *a)
{
	a->h = 0;
	a->l = 0;
}

static uint64_t g_cmp_count = 0;

static bool key_cmp(htable_key_t a, htable_key_t b)
{
	g_cmp_count++;
	return (a.h == b.h && a.l == b.l);
}

static void htable_swap(htable_index_t a, htable_index_t b)
{
	// swap keys
	htable_key_t tmpk = g_keys[a];
	g_keys[a] = g_keys[b];
	g_keys[b] = tmpk;

	// swap vals
	int tmpv = g_vals[a];
	g_vals[a] = g_vals[b];
	g_vals[b] = tmpv;
}

static uint64_t htable_hash(htable_key_t data)
{
	uint64_t z = data.h ^ data.l;
	// splitmix64
	/* xor the variable with the variable right bit shifted 30 then multiply by a constant */
	z = (z ^ (z >> 30)) * 0xbf58476d1ce4e5b9;
	/* xor the variable with the variable right bit shifted 27 then multiply by a constant */
	z = (z ^ (z >> 27)) * 0x94d049bb133111eb;
	/* return the variable xored with itself right bit shifted 31 */
	return z ^ (z >> 31);
}

#define STATISTICS 1
#include "../linear_probing.h"

// ------------------------------------------------------------
// Helpers
// ------------------------------------------------------------

static void clear_table(void)
{
	for (size_t i = 0; i < TABLE_SIZE; ++i) {
		key_set_null(&g_keys[i]);
		g_vals[i] = 0xDEADBEEF;
	}
}

static htable_key_t make_key(uint64_t a, uint64_t b)
{
	htable_key_t k;
	k.h = a;
	k.l = b;
	return k;
}

static htable_index_t key_home_index(htable_key_t k)
{
	return lp_home_index(htable_hash(k), TABLE_SIZE);
}

static htable_key_t make_key_for_home(htable_index_t desired_home,
				      uint64_t salt)
{
	for (size_t tweak = 1; tweak != 0; ++tweak) {
		htable_key_t candidate = make_key(salt, tweak);
		if (key_home_index(candidate) == desired_home) {
			return candidate;
		}
	}
	assert(!"failed to synthesize key for desired home index");
	return make_key(0, 0);
}

static void insert_no_overflow(htable_key_t k, int v)
{
	htable_index_t slot = lp_find_free_slot(g_keys, k, TABLE_SIZE);

	if (slot >= TABLE_SIZE) {
		LOGE("TABLE IS FULL OR INVALID SLOT RETURNED!");
		return;
	}

	if (!key_is_null(g_keys[slot])) {
		LOGE("SLOT IS NOT EMPTY!");
		return;
	}

	g_keys[slot] = k;
	g_vals[slot] = v;
}

static bool erase_existing(htable_key_t k)
{
	htable_index_t idx = lp_lookup(g_keys, k, TABLE_SIZE);
	if (idx == TABLE_SIZE) {
		LOGE("NOT FOUND");
		return false;
	}
	htable_index_t hole = lp_erase(g_keys, idx, TABLE_SIZE);
	g_vals[hole] = 0xDEADBEEF;
	return true;
}

static bool check_value(htable_key_t k, int expect_v)
{
	htable_index_t idx = lp_lookup(g_keys, k, TABLE_SIZE);
	if (idx == TABLE_SIZE) {
		return false;
	}
	if (!key_cmp(g_keys[idx], k)) {
		return false;
	}
	if (g_vals[idx] != expect_v) {
		return false;
	}
	return true;
}

// ------------------------------------------------------------
// ASSERT
// ------------------------------------------------------------
static int g_total = 0;
static int g_failed = 0;

static void TASSERT(bool cond, const char *msg)
{
	g_total++;
	if (!cond) {
		g_failed++;
		LOGE("[FAIL] %s", msg);
	}
}

// ------------------------------------------------------------
// TESTS
// ------------------------------------------------------------

static void test_basic_insert_lookup(void)
{
	LOGD("\n===========\nstart\n");
	clear_table();

	htable_key_t k1 = make_key(1, 100);
	htable_key_t k2 = make_key(2, 200);
	htable_key_t k3 = make_key(3, 300);

	insert_no_overflow(k1, 42);
	insert_no_overflow(k2, 55);
	insert_no_overflow(k3, 99);

	TASSERT(check_value(k1, 42), "lookup k1 after insert");
	TASSERT(check_value(k2, 55), "lookup k2 after insert");
	TASSERT(check_value(k3, 99), "lookup k3 after insert");

	htable_key_t k4 = make_key(4, 400);
	htable_index_t idx4 = lp_lookup(g_keys, k4, TABLE_SIZE);
	TASSERT(idx4 == TABLE_SIZE, "lookup of absent key should fail");
}

static void test_linear_probe_cluster(void)
{
	LOGD("\n===========\nstart\n");
	clear_table();

	for (size_t i = 0; i < 8; ++i) {
		htable_key_t k = make_key(12345ULL, (uint64_t)i);
		insert_no_overflow(k, (int)(i * 10));
	}

	for (size_t i = 0; i < 8; ++i) {
		htable_key_t k = make_key(12345ULL, (uint64_t)i);
		char msg[128];
		snprintf(msg, sizeof(msg), "cluster lookup key #%zu", i);
		TASSERT(check_value(k, (int)(i * 10)), msg);
	}
}

static void test_erase_and_cluster_compaction(void)
{
	LOGD("\n===========\nstart\n");
	clear_table();

	htable_key_t ks[6];
	for (size_t i = 0; i < 6; ++i) {
		ks[i] = make_key(999ULL, (uint64_t)i);
		insert_no_overflow(ks[i], (int)(1000 + i));
	}

	for (size_t i = 0; i < 6; ++i) {
		char msg[128];
		snprintf(msg, sizeof(msg), "pre-erase lookup k[%zu]", i);
		TASSERT(check_value(ks[i], (int)(1000 + i)), msg);
	}

	bool erased = erase_existing(ks[2]);
	TASSERT(erased, "erase_existing ks[2] should return true");

	htable_index_t idx2 = lp_lookup(g_keys, ks[2], TABLE_SIZE);
	TASSERT(idx2 == TABLE_SIZE, "ks[2] should be gone after erase");

	for (size_t i = 0; i < 6; ++i) {
		if (i == 2)
			continue;
		char msg[128];
		snprintf(msg, sizeof(msg), "post-erase lookup k[%zu]", i);
		TASSERT(check_value(ks[i], (int)(1000 + i)), msg);
	}
}

static void test_reuse_after_erase(void)
{
	LOGD("\n===========\nstart\n");
	clear_table();

	htable_key_t kA = make_key(111ULL, 1ULL);
	htable_key_t kB = make_key(111ULL, 2ULL);
	htable_key_t kC = make_key(111ULL, 3ULL);

	insert_no_overflow(kA, 10);
	insert_no_overflow(kB, 20);
	insert_no_overflow(kC, 30);

	bool erased = erase_existing(kB);
	TASSERT(erased, "kB erased");

	htable_index_t idxB = lp_lookup(g_keys, kB, TABLE_SIZE);
	TASSERT(idxB == TABLE_SIZE, "kB must be missing");

	TASSERT(check_value(kA, 10), "kA still OK after erase B");
	TASSERT(check_value(kC, 30), "kC still OK after erase B");

	htable_key_t kD = make_key(111ULL, 4ULL);
	insert_no_overflow(kD, 40);
	TASSERT(check_value(kD, 40), "kD inserted after erase");
}

static void test_null_behavior(void)
{
	LOGD("\n===========\nstart\n");
	clear_table();

	for (size_t i = 0; i < TABLE_SIZE; ++i) {
		char msg[128];
		snprintf(msg, sizeof(msg), "initial slot %zu is null", i);
		TASSERT(key_is_null(g_keys[i]), msg);
	}

	htable_key_t kk = make_key(777, 888);
	htable_index_t idx = lp_lookup(g_keys, kk, TABLE_SIZE);
	TASSERT(idx == TABLE_SIZE, "lookup in empty table returns not found");
}

static void test_find_free_slot_wraparound(void)
{
	LOGD("\n===========\nstart\n");
	clear_table();

	const htable_index_t tail_home = TABLE_SIZE - 2;
	htable_key_t tail_key = make_key_for_home(tail_home, 1001);
	htable_key_t tail_guard = make_key_for_home(TABLE_SIZE - 1, 2001);
	htable_key_t wrap_key = make_key_for_home(tail_home, 3001);

	insert_no_overflow(tail_key, 10);
	insert_no_overflow(tail_guard, 20);

	htable_index_t slot = lp_find_free_slot(g_keys, wrap_key, TABLE_SIZE);
	TASSERT(slot == 0,
		"lp_find_free_slot must wrap when tail cluster blocks tail");

	g_keys[slot] = wrap_key;
	g_vals[slot] = 30;

	htable_index_t lookup_idx = lp_lookup(g_keys, wrap_key, TABLE_SIZE);
	TASSERT(lookup_idx == slot,
		"lookup succeeds for key placed after wraparound insert");
}

static void test_lookup_wraparound(void)
{
	LOGD("\n===========\nstart\n");
	clear_table();

	const htable_index_t crowded_home = TABLE_SIZE - 2;
	htable_key_t k1 = make_key_for_home(crowded_home, 4001);
	htable_key_t k2 = make_key_for_home(crowded_home, 4002);
	htable_key_t k3 = make_key_for_home(crowded_home, 4003);

	insert_no_overflow(k1, 11);
	insert_no_overflow(k2, 22);
	insert_no_overflow(k3, 33);

	TASSERT(key_home_index(k3) == crowded_home,
		"precondition: target key home index");

	htable_index_t idx = lp_lookup(g_keys, k3, TABLE_SIZE);
	TASSERT(idx == 0, "lp_lookup must scan wrapped section and locate key");
	TASSERT(check_value(k3, 33),
		"lp_lookup returns correct value after wrapping");
}

static void test_erase_wraparound_path(void)
{
	LOGD("\n===========\nstart\n");
	clear_table();

	const htable_index_t cluster_home = 10;
	const size_t cluster_len = 7;
	htable_key_t cluster[cluster_len];

	for (size_t i = 0; i < cluster_len; ++i) {
		cluster[i] = make_key_for_home(cluster_home, 5000 + i);
		insert_no_overflow(cluster[i], (int)(100 + i));
	}

	htable_index_t victim_idx = lp_lookup(g_keys, cluster[0], TABLE_SIZE);
	TASSERT(victim_idx == cluster_home,
		"precondition: victim resides at its home slot");

	(void)lp_erase(g_keys, victim_idx, TABLE_SIZE);

	htable_index_t lookup_deleted =
		lp_lookup(g_keys, cluster[0], TABLE_SIZE);
	TASSERT(lookup_deleted == TABLE_SIZE,
		"erased key should not be found after wraparound erase");

	for (size_t i = 1; i < cluster_len; ++i) {
		char msg[128];
		snprintf(msg, sizeof(msg),
			 "cluster key %zu survives wraparound erase", i);
		TASSERT(check_value(cluster[i], (int)(100 + i)), msg);
	}
}

static void test_erase_wraparound_5()
{
	LOGD("\n===========\nstart\n");
	clear_table();

	TASSERT(TABLE_SIZE >= 5,
		"test requires TABLE_SIZE >= 5 (so that N-2, N-1,0,1,2 all exist)");

	htable_index_t desired_home = TABLE_SIZE - 2;

	htable_key_t k1 = make_key_for_home(desired_home, 1001);
	htable_key_t k2 = make_key_for_home(desired_home, 2002);
	htable_key_t k3 = make_key_for_home(desired_home, 3003);
	htable_key_t k4 = make_key_for_home(desired_home, 4004);
	htable_key_t k5 = make_key_for_home(desired_home, 5005);

	TASSERT(key_home_index(k1) == desired_home, "k1 home ok");
	TASSERT(key_home_index(k2) == desired_home, "k2 home ok");
	TASSERT(key_home_index(k3) == desired_home, "k3 home ok");
	TASSERT(key_home_index(k4) == desired_home, "k4 home ok");
	TASSERT(key_home_index(k5) == desired_home, "k5 home ok");

	insert_no_overflow(k1, 11);
	insert_no_overflow(k2, 22);
	insert_no_overflow(k3, 33);
	insert_no_overflow(k4, 44);
	insert_no_overflow(k5, 55);

	TASSERT(check_value(k1, 11), "k1 before erase");
	TASSERT(check_value(k2, 22), "k2 before erase");
	TASSERT(check_value(k3, 33), "k3 before erase");
	TASSERT(check_value(k4, 44), "k4 before erase");
	TASSERT(check_value(k5, 55), "k5 before erase");

	{
		htable_index_t idx1 = lp_lookup(g_keys, k1, TABLE_SIZE);
		TASSERT(idx1 == desired_home,
			"k1 is sitting exactly at TABLE_SIZE-2 before erase");
	}

	TASSERT(erase_existing(k1), "erase_existing(k1) should succeed");

	TASSERT(check_value(k2, 22),
		"k2 must still be reachable after erase(k1)");

	TASSERT(check_value(k3, 33),
		"k3 must still be reachable after erase(k1)");

	TASSERT(check_value(k4, 44),
		"k4 must still be reachable after erase(k1) -- ");

	TASSERT(check_value(k5, 55),
		"k5 must still be reachable after erase(k1) -- ");
}

static void test_erase_breaks_wraparound_with_foreign_zero(void)
{
	LOGD("\n===========\nTEST: lp_erase wraparound w/ foreign [0]\n");
	clear_table();

	TASSERT(TABLE_SIZE >= 5,
		"TABLE_SIZE must be >=5 for this test (need N-2,N-1,0,1,2)");

	htable_index_t desired_home = TABLE_SIZE - 2;

	htable_key_t z0 = make_key_for_home(0, 9001);

	htable_key_t k1 = make_key_for_home(desired_home, 1001);
	htable_key_t k2 = make_key_for_home(desired_home, 2002);
	htable_key_t k3 = make_key_for_home(desired_home, 3003);
	htable_key_t k4 = make_key_for_home(desired_home, 4004);

	TASSERT(key_home_index(z0) == 0, "z0 has home=0");

	TASSERT(key_home_index(k1) == desired_home, "k1 has expected home");
	TASSERT(key_home_index(k2) == desired_home, "k2 has expected home");
	TASSERT(key_home_index(k3) == desired_home, "k3 has expected home");
	TASSERT(key_home_index(k4) == desired_home, "k4 has expected home");

	insert_no_overflow(z0, 999);

	insert_no_overflow(k1, 11);
	insert_no_overflow(k2, 22);
	insert_no_overflow(k3, 33);
	insert_no_overflow(k4, 44);

	TASSERT(check_value(z0, 999), "z0 before erase");
	TASSERT(check_value(k1, 11), "k1 before erase");
	TASSERT(check_value(k2, 22), "k2 before erase");
	TASSERT(check_value(k3, 33), "k3 before erase");
	TASSERT(check_value(k4, 44), "k4 before erase");

	{
		htable_index_t idx1 = lp_lookup(g_keys, k1, TABLE_SIZE);
		TASSERT(idx1 == desired_home,
			"k1 landed exactly at TABLE_SIZE-2 as expected");
	}

	TASSERT(erase_existing(k1), "erase_existing(k1) must succeed");

	TASSERT(check_value(z0, 999),
		"z0 should still be there and reachable after erase(k1)");

	TASSERT(check_value(k2, 22),
		"k2 should still be reachable after erase(k1)");

	TASSERT(check_value(k3, 33),
		"k3 must still be reachable after erase(k1) ");

	TASSERT(check_value(k4, 44),
		"k4 must still be reachable after erase(k1) ");
}

static void test_lookup_empty_home_with_adjacent_cluster(void)
{
	LOGD("\n===========\nTEST: lookup with empty home and adjacent cluster\n");
	clear_table();

	const htable_index_t empty_home = 2;
	const htable_index_t adjacent_home = 3;

	htable_key_t missing_key = make_key_for_home(empty_home, 7001);
	htable_key_t adj1 = make_key_for_home(adjacent_home, 8001);
	htable_key_t adj2 = make_key_for_home(adjacent_home, 8002);

	insert_no_overflow(adj1, 100);
	insert_no_overflow(adj2, 200);

	TASSERT(key_is_null(g_keys[empty_home]),
		"empty_home slot 2 must be null");
	TASSERT(!key_is_null(g_keys[adjacent_home]),
		"adjacent slot 3 occupied");
	TASSERT(!key_is_null(g_keys[(adjacent_home + 1) % TABLE_SIZE]),
		"adjacent slot 4 occupied");

	htable_index_t idx = lp_lookup(g_keys, missing_key, TABLE_SIZE);
	TASSERT(idx == TABLE_SIZE,
		"missing key lookup must immediately return not found when home is null");
}

static void test_erase_isolated_element(void)
{
	LOGD("\n===========\nTEST: erase isolated element\n");
	clear_table();

	htable_index_t isolated_home = 5;
	htable_key_t k = make_key_for_home(isolated_home, 1234);
	insert_no_overflow(k, 42);

	TASSERT(check_value(k, 42), "isolated key reachable");
	TASSERT(erase_existing(k), "erase isolated key succeeds");

	TASSERT(lp_lookup(g_keys, k, TABLE_SIZE) == TABLE_SIZE,
		"isolated key lookup fails after erase");
	TASSERT(key_is_null(g_keys[isolated_home]),
		"isolated key slot restored to null");
	TASSERT(g_vals[isolated_home] == (int)0xDEADBEEF,
		"isolated value wiped on erase");
}

static void test_lookup_null_key_in_empty_table(void)
{
	LOGD("\n===========\nBUG TEST: lookup null key in empty table\n");
	clear_table();

	htable_key_t null_key = make_key(0, 0);
	htable_index_t idx = lp_lookup(g_keys, null_key, TABLE_SIZE);

	TASSERT(idx == TABLE_SIZE,
		"lookup of null key in an empty table must return TABLE_SIZE");
}

static void test_unnecessary_probes_on_empty_home(void)
{
	LOGD("\n===========\nBUG TEST: unnecessary cluster scan when home is empty\n");
	clear_table();

	// Populate an adjacent cluster at slots 3, 4, 5, 6 (all hashing to home 3)
	htable_key_t c1 = make_key_for_home(3, 100);
	htable_key_t c2 = make_key_for_home(3, 200);
	htable_key_t c3 = make_key_for_home(3, 300);
	htable_key_t c4 = make_key_for_home(3, 400);

	insert_no_overflow(c1, 1);
	insert_no_overflow(c2, 2);
	insert_no_overflow(c3, 3);
	insert_no_overflow(c4, 4);

	// Slot 2 is completely empty and is the home slot for missing_key
	htable_key_t missing_key = make_key_for_home(2, 999);
	TASSERT(key_is_null(g_keys[2]), "precondition: slot 2 is null");

	// Reset probe counter
	g_cmp_count = 0;
	htable_index_t idx = lp_lookup(g_keys, missing_key, TABLE_SIZE);

	TASSERT(idx == TABLE_SIZE, "missing key returns not found");

	// If slot 2 is empty, it must not probe into slots 3, 4, 5, 6!
	// Current code calls key_cmp 5 times (slot 2, 3, 4, 5, 6).
	TASSERT(g_cmp_count <= 1,
		"lookup must not scan adjacent cluster when home slot is null");
}

static void test_statistics_overcounting(void)
{
	LOGD("\n===========\nBUG TEST: statistics off-by-one overcounting\n");
	clear_table();
	memset(&lp_statistics, 0, sizeof(lp_statistics));

	// k1 occupies slot 0
	htable_key_t k1 = make_key_for_home(0, 100);
	insert_no_overflow(k1, 10);

	// k2 also hashes to slot 0.
	// Slot 0 is occupied, slot 1 is free -> displacement distance is exactly 1.
	htable_key_t k2 = make_key_for_home(0, 200);
	insert_no_overflow(k2, 20);

	TASSERT(lp_statistics.total_went_due_to_collisions == 1,
		"total_went_due_to_collisions must be 1 for a 1-slot displacement");
}

// ------------------------------------------------------------
// MAIN
// ------------------------------------------------------------
int main(void)
{
	printf("Running lp_test...\n");

	test_null_behavior();
	test_find_free_slot_wraparound();
	test_lookup_wraparound();
	test_erase_wraparound_path();
	test_basic_insert_lookup();
	test_linear_probe_cluster();
	test_erase_and_cluster_compaction();
	test_reuse_after_erase();
	test_erase_wraparound_5();
	test_erase_breaks_wraparound_with_foreign_zero();
	test_lookup_empty_home_with_adjacent_cluster();
	test_erase_isolated_element();
	test_lookup_null_key_in_empty_table();
	test_unnecessary_probes_on_empty_home();
	test_statistics_overcounting();

	printf("TOTAL ASSERTS: %d\n", g_total);
	printf("FAILED ASSERTS: %d\n", g_failed);
	if (g_failed == 0) {
		printf("RESULT: SUCCESS ✅\n");
		return 0;
	} else {
		printf("RESULT: FAIL ❌\n");
		return 1;
	}
}
