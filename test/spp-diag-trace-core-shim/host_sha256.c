/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * FIPS 180-4 SHA-256. Host-only stand-in for CRYPTO_LIB_SHA256.
 */

#include <crypto/sha2.h>
#include <linux/string.h>
#include <linux/types.h>

static u32 rotr32(u32 value, unsigned int bits)
{
	return (value >> bits) | (value << (32 - bits));
}

static u32 load_be32(const u8 *p)
{
	return ((u32)p[0] << 24) | ((u32)p[1] << 16) | ((u32)p[2] << 8) |
	       (u32)p[3];
}

static void store_be32(u8 *p, u32 value)
{
	p[0] = (u8)(value >> 24);
	p[1] = (u8)(value >> 16);
	p[2] = (u8)(value >> 8);
	p[3] = (u8)value;
}

static const u32 k_sha256[64] = {
	0x428a2f98u, 0x71374491u, 0xb5c0fbcfu, 0xe9b5dba5u, 0x3956c25bu,
	0x59f111f1u, 0x923f82a4u, 0xab1c5ed5u, 0xd807aa98u, 0x12835b01u,
	0x243185beu, 0x550c7dc3u, 0x72be5d74u, 0x80deb1feu, 0x9bdc06a7u,
	0xc19bf174u, 0xe49b69c1u, 0xefbe4786u, 0x0fc19dc6u, 0x240ca1ccu,
	0x2de92c6fu, 0x4a7484aau, 0x5cb0a9dcu, 0x76f988dau, 0x983e5152u,
	0xa831c66du, 0xb00327c8u, 0xbf597fc7u, 0xc6e00bf3u, 0xd5a79147u,
	0x06ca6351u, 0x14292967u, 0x27b70a85u, 0x2e1b2138u, 0x4d2c6dfcu,
	0x53380d13u, 0x650a7354u, 0x766a0abbu, 0x81c2c92eu, 0x92722c85u,
	0xa2bfe8a1u, 0xa81a664bu, 0xc24b8b70u, 0xc76c51a3u, 0xd192e819u,
	0xd6990624u, 0xf40e3585u, 0x106aa070u, 0x19a4c116u, 0x1e376c08u,
	0x2748774cu, 0x34b0bcb5u, 0x391c0cb3u, 0x4ed8aa4au, 0x5b9cca4fu,
	0x682e6ff3u, 0x748f82eeu, 0x78a5636fu, 0x84c87814u, 0x8cc70208u,
	0x90befffau, 0xa4506cebu, 0xbef9a3f7u, 0xc67178f2u,
};

static void sha256_compress(u32 state[8], const u8 block[64])
{
	u32 w[64];
	u32 a, b, c, d, e, f, g, h;
	unsigned int i;

	for (i = 0; i < 16; i++)
		w[i] = load_be32(block + i * 4);
	for (i = 16; i < 64; i++) {
		u32 s0 = rotr32(w[i - 15], 7) ^ rotr32(w[i - 15], 18) ^
			 (w[i - 15] >> 3);
		u32 s1 = rotr32(w[i - 2], 17) ^ rotr32(w[i - 2], 19) ^
			 (w[i - 2] >> 10);
		w[i] = w[i - 16] + s0 + w[i - 7] + s1;
	}
	a = state[0];
	b = state[1];
	c = state[2];
	d = state[3];
	e = state[4];
	f = state[5];
	g = state[6];
	h = state[7];
	for (i = 0; i < 64; i++) {
		u32 S1 = rotr32(e, 6) ^ rotr32(e, 11) ^ rotr32(e, 25);
		u32 ch = (e & f) ^ ((~e) & g);
		u32 temp1 = h + S1 + ch + k_sha256[i] + w[i];
		u32 S0 = rotr32(a, 2) ^ rotr32(a, 13) ^ rotr32(a, 22);
		u32 maj = (a & b) ^ (a & c) ^ (b & c);
		u32 temp2 = S0 + maj;
		h = g;
		g = f;
		f = e;
		e = d + temp1;
		d = c;
		c = b;
		b = a;
		a = temp1 + temp2;
	}
	state[0] += a;
	state[1] += b;
	state[2] += c;
	state[3] += d;
	state[4] += e;
	state[5] += f;
	state[6] += g;
	state[7] += h;
}

#define HOST_SHA256_PREIMAGE_MAX 1151u
#define HOST_SHA256_RING 8u

static unsigned sha_call_count;
static unsigned sha_preimage_n;
static unsigned sha_preimage_lens[HOST_SHA256_RING];
static u8 sha_preimages[HOST_SHA256_RING][HOST_SHA256_PREIMAGE_MAX];
static unsigned sha_sentinel_count;
static unsigned sha_sentinel_idx;
static u8 sha_sentinels[HOST_SHA256_RING][32];

void host_sha256_reset_instrumentation(void)
{
	sha_call_count = 0;
	sha_preimage_n = 0;
	sha_sentinel_count = 0;
	sha_sentinel_idx = 0;
}

unsigned host_sha256_call_count(void)
{
	return sha_call_count;
}

void host_sha256_push_sentinel(const u8 digest[32])
{
	if (sha_sentinel_count >= HOST_SHA256_RING)
		return;
	memcpy(sha_sentinels[sha_sentinel_count], digest, 32);
	sha_sentinel_count++;
}

unsigned host_sha256_preimage_count(void)
{
	return sha_preimage_n;
}

int host_sha256_get_preimage(unsigned i, u8 *out, unsigned *len)
{
	unsigned n;

	if (i >= sha_preimage_n || out == NULL || len == NULL)
		return 0;
	n = sha_preimage_lens[i];
	if (n > HOST_SHA256_PREIMAGE_MAX)
		n = HOST_SHA256_PREIMAGE_MAX;
	memcpy(out, sha_preimages[i], n);
	*len = sha_preimage_lens[i];
	return 1;
}

static void sha256_compute(const u8 *data, unsigned int len, u8 *out)
{
	u32 state[8] = {
		0x6a09e667u, 0xbb67ae85u, 0x3c6ef372u, 0xa54ff53au,
		0x510e527fu, 0x9b05688cu, 0x1f83d9abu, 0x5be0cd19u,
	};
	u8 block[64];
	unsigned int offset = 0;
	u64 bit_len = (u64)len * 8u;

	while (len - offset >= 64u) {
		sha256_compress(state, data + offset);
		offset += 64u;
	}
	memset(block, 0, sizeof(block));
	memcpy(block, data + offset, len - offset);
	block[len - offset] = 0x80;
	if (len - offset >= 56u) {
		sha256_compress(state, block);
		memset(block, 0, sizeof(block));
	}
	store_be32(block + 56, (u32)(bit_len >> 32));
	store_be32(block + 60, (u32)bit_len);
	sha256_compress(state, block);
	for (offset = 0; offset < 8; offset++)
		store_be32(out + offset * 4, state[offset]);
}

void sha256(const u8 *data, unsigned int len, u8 *out)
{
	unsigned slot;
	unsigned n;

	sha_call_count++;
	if (sha_preimage_n < HOST_SHA256_RING) {
		slot = sha_preimage_n++;
		sha_preimage_lens[slot] = len;
		n = len;
		if (n > HOST_SHA256_PREIMAGE_MAX)
			n = HOST_SHA256_PREIMAGE_MAX;
		if (n && data != NULL)
			memcpy(sha_preimages[slot], data, n);
	}
	if (sha_sentinel_idx < sha_sentinel_count) {
		memcpy(out, sha_sentinels[sha_sentinel_idx], 32);
		sha_sentinel_idx++;
		return;
	}
	sha256_compute(data, len, out);
}
