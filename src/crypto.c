/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2012-2014  Intel Corporation. All rights reserved.
 *
 *
 *  This library is free software; you can redistribute it and/or
 *  modify it under the terms of the GNU Lesser General Public
 *  License as published by the Free Software Foundation; either
 *  version 2.1 of the License, or (at your option) any later version.
 *
 *  This library is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *  Lesser General Public License for more details.
 *
 *  You should have received a copy of the GNU Lesser General Public
 *  License along with this library; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 *
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <sys/socket.h>

#include "src/shared/util.h"
#include "src/shared/crypto.h"

struct bt_crypto {
	int ref_count;
	int ecb_aes;
	int urandom;
	int cmac_aes;
};

#ifndef HAVE_LINUX_IF_ALG_H
#ifndef HAVE_LINUX_TYPES_H
typedef uint8_t __u8;
typedef uint16_t __u16;
typedef uint32_t __u32;
#else
#include <linux/types.h>
#endif
struct af_alg_iv {
	__u32   ivlen;
	__u8    iv[0];
};

#define ALG_SET_KEY                     1
#define ALG_SET_IV                      2
#define ALG_SET_OP                      3

#define ALG_OP_DECRYPT                  0
#define ALG_OP_ENCRYPT                  1

#define PF_ALG		38	/* Algorithm sockets.  */
#define AF_ALG		PF_ALG
#else
#include <linux/if_alg.h>
#endif

#ifndef SOL_ALG
#define SOL_ALG		279
#endif

struct sockaddr_alg {
	__u16   salg_family;
	__u8    salg_type[14];
	__u32   salg_feat;
	__u32   salg_mask;
	__u8    salg_name[64];
};

static int ecb_aes_setup(void)
{
	struct sockaddr_alg salg;
	int fd;

	fd = socket(PF_ALG, SOCK_SEQPACKET | SOCK_CLOEXEC, 0);
	if (fd < 0)
		return -1;

	memset(&salg, 0, sizeof(salg));
	salg.salg_family = AF_ALG;
	strcpy((char *) salg.salg_type, "skcipher");
	strcpy((char *) salg.salg_name, "ecb(aes)");

	if (bind(fd, (struct sockaddr *) &salg, sizeof(salg)) < 0) {
		close(fd);
		return -1;
	}

	return fd;
}

static int urandom_setup(void)
{
	int fd;

	fd = open("/dev/urandom", O_RDONLY);
	if (fd < 0)
		return -1;

	return fd;
}

static int cmac_aes_setup(void)
{
	struct sockaddr_alg salg;
	int fd;

	fd = socket(PF_ALG, SOCK_SEQPACKET | SOCK_CLOEXEC, 0);
	if (fd < 0)
		return -1;

	memset(&salg, 0, sizeof(salg));
	salg.salg_family = AF_ALG;
	strcpy((char *) salg.salg_type, "hash");
	strcpy((char *) salg.salg_name, "cmac(aes)");

	if (bind(fd, (struct sockaddr *) &salg, sizeof(salg)) < 0) {
		close(fd);
		return -1;
	}

	return fd;
}

static inline void swap_buf(const uint8_t *src, uint8_t *dst, uint16_t len)
{
	int i;

	for (i = 0; i < len; i++)
		dst[len - 1 - i] = src[i];
}

static int alg_new(int fd, const void *keyval, socklen_t keylen)
{
	if (setsockopt(fd, SOL_ALG, ALG_SET_KEY, keyval, keylen) < 0)
		return -1;

	/* FIXME: This should use accept4() with SOCK_CLOEXEC */
	return accept(fd, NULL, 0);
}

bool bt_crypto_sign_att(struct bt_crypto *crypto, const uint8_t key[16],
				const uint8_t *m, uint16_t m_len,
				uint32_t sign_cnt, uint8_t signature[12])
{
	int fd;
	int len;
	uint8_t tmp[16], out[16];
	uint16_t msg_len = m_len + sizeof(uint32_t);
	uint8_t msg[msg_len];
	uint8_t msg_s[msg_len];

	if (!crypto)
		return false;

	memset(msg, 0, msg_len);
	memcpy(msg, m, m_len);

	/* Add sign_counter to the message */
	put_le32(sign_cnt, msg + m_len);

	/* The most significant octet of key corresponds to key[0] */
	swap_buf(key, tmp, 16);

	fd = alg_new(crypto->cmac_aes, tmp, 16);
	if (fd < 0)
		return false;

	/* Swap msg before signing */
	swap_buf(msg, msg_s, msg_len);

	len = send(fd, msg_s, msg_len, 0);
	if (len < 0) {
		close(fd);
		return false;
	}

	len = read(fd, out, 16);
	if (len < 0) {
		close(fd);
		return false;
	}

	close(fd);

	/*
	 * As to BT spec. 4.1 Vol[3], Part C, chapter 10.4.1 sign counter should
	 * be placed in the signature
	 */
	put_be32(sign_cnt, out + 8);

	/*
	 * The most significant octet of hash corresponds to out[0]  - swap it.
	 * Then truncate in most significant bit first order to a length of
	 * 12 octets
	 */
	swap_buf(out, tmp, 16);
	memcpy(signature, tmp + 4, 12);

	return true;
}

struct bt_crypto *bt_crypto_new(void)
{
	struct bt_crypto *crypto;

	crypto = new0(struct bt_crypto, 1);

	crypto->ecb_aes = ecb_aes_setup();
	if (crypto->ecb_aes < 0) {
		free(crypto);
		return NULL;
	}

	crypto->urandom = urandom_setup();
	if (crypto->urandom < 0) {
		close(crypto->ecb_aes);
		free(crypto);
		return NULL;
	}

	crypto->cmac_aes = cmac_aes_setup();
	if (crypto->cmac_aes < 0) {
		close(crypto->urandom);
		close(crypto->ecb_aes);
		free(crypto);
		return NULL;
	}

	return bt_crypto_ref(crypto);
}

struct bt_crypto *bt_crypto_ref(struct bt_crypto *crypto)
{
	if (!crypto)
		return NULL;

	__sync_fetch_and_add(&crypto->ref_count, 1);

	return crypto;
}

void bt_crypto_unref(struct bt_crypto *crypto)
{
	if (!crypto)
		return;

	if (__sync_sub_and_fetch(&crypto->ref_count, 1))
		return;

	close(crypto->urandom);
	close(crypto->ecb_aes);
	close(crypto->cmac_aes);

	free(crypto);
}

