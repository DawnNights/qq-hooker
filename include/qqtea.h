// From https://github.com/super1207/qqtea
#pragma once
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <windows.h>

#if (defined(_WIN16) || defined(_WIN32) || defined(_WIN64)) && !defined(__WINDOWS__)

#define __WINDOWS__

#endif

#if defined(__linux__) || defined(__CYGWIN__)

#include <endian.h>

#elif defined(__APPLE__)

#include <libkern/OSByteOrder.h>

#define htobe16(x) OSSwapHostToBigInt16(x)
#define htole16(x) OSSwapHostToLittleInt16(x)
#define be16toh(x) OSSwapBigToHostInt16(x)
#define le16toh(x) OSSwapLittleToHostInt16(x)

#define htobe32(x) OSSwapHostToBigInt32(x)
#define htole32(x) OSSwapHostToLittleInt32(x)
#define be32toh(x) OSSwapBigToHostInt32(x)
#define le32toh(x) OSSwapLittleToHostInt32(x)

#define htobe64(x) OSSwapHostToBigInt64(x)
#define htole64(x) OSSwapHostToLittleInt64(x)
#define be64toh(x) OSSwapBigToHostInt64(x)
#define le64toh(x) OSSwapLittleToHostInt64(x)

#define __BYTE_ORDER BYTE_ORDER
#define __BIG_ENDIAN BIG_ENDIAN
#define __LITTLE_ENDIAN LITTLE_ENDIAN
#define __PDP_ENDIAN PDP_ENDIAN

#elif defined(__OpenBSD__)

#include <sys/endian.h>

#elif defined(__NetBSD__) || defined(__FreeBSD__) || defined(__DragonFly__)

#include <sys/endian.h>

#define be16toh(x) betoh16(x)
#define le16toh(x) letoh16(x)

#define be32toh(x) betoh32(x)
#define le32toh(x) letoh32(x)

#define be64toh(x) betoh64(x)
#define le64toh(x) letoh64(x)

#elif defined(__WINDOWS__)

#include <windows.h>

#if BYTE_ORDER == LITTLE_ENDIAN

#if defined(_MSC_VER)
#include <stdlib.h>
#define htobe16(x) _byteswap_ushort(x)
#define htole16(x) (x)
#define be16toh(x) _byteswap_ushort(x)
#define le16toh(x) (x)

#define htobe32(x) _byteswap_ulong(x)
#define htole32(x) (x)
#define be32toh(x) _byteswap_ulong(x)
#define le32toh(x) (x)

#define htobe64(x) _byteswap_uint64(x)
#define htole64(x) (x)
#define be64toh(x) _byteswap_uint64(x)
#define le64toh(x) (x)

#elif defined(__GNUC__) || defined(__clang__)

#define htobe16(x) __builtin_bswap16(x)
#define htole16(x) (x)
#define be16toh(x) __builtin_bswap16(x)
#define le16toh(x) (x)

#define htobe32(x) __builtin_bswap32(x)
#define htole32(x) (x)
#define be32toh(x) __builtin_bswap32(x)
#define le32toh(x) (x)

#define htobe64(x) __builtin_bswap64(x)
#define htole64(x) (x)
#define be64toh(x) __builtin_bswap64(x)
#define le64toh(x) (x)
#else
#error platform not supported
#endif

#else

#error byte order not supported

#endif

#define __BYTE_ORDER BYTE_ORDER
#define __BIG_ENDIAN BIG_ENDIAN
#define __LITTLE_ENDIAN LITTLE_ENDIAN
#define __PDP_ENDIAN PDP_ENDIAN

#else

#error platform not supported

#endif

/*
 * 描述:用qqtea来加密
 * 参数key:长度必须为16
 * 参数out_buf_len:加密后的数据长度
 * 返回值:加密后的数据，使用qqtea_free来释放
 */
unsigned char *qqtea_encode(const unsigned char *key, const unsigned char *buffer, uint32_t len, uint32_t *out_buf_len)
{
    const uint32_t fill = (8 - (len + 2)) % 8 + 2;
    const uint32_t ret_buf_len = 1 + fill + len + 7;
    unsigned char *ret_buffer = (unsigned char *)malloc(ret_buf_len);
    if (!ret_buffer)
    {
        (*out_buf_len) = 0;
        return NULL;
    }
    ret_buffer[0] = ((uint8_t)(fill - 2)) | 0xF8;
    /* memset(ret_buffer+1,0xAD,fill); */
    memcpy(ret_buffer + fill + 1, buffer, len);
    memset(ret_buffer + 1 + fill + len, '\0', 7);
    uint32_t t0 = be32toh(*((uint32_t *)&key[0]));
    uint32_t t1 = be32toh(*((uint32_t *)&key[4]));
    uint32_t t2 = be32toh(*((uint32_t *)&key[8]));
    uint32_t t3 = be32toh(*((uint32_t *)&key[12]));
    uint64_t iv1 = 0, iv2 = 0, holder;
    for (uint32_t i = 0; i < ret_buf_len; i += 8)
    {
        uint64_t block = be64toh(*((uint64_t *)&ret_buffer[i]));
        holder = block ^ iv1;
        {
            uint32_t v0 = (uint32_t)(holder >> 32);
            uint32_t v1 = (uint32_t)(holder);
            v0 += (v1 + 0x9e3779b9) ^ ((v1 << 4) + t0) ^ ((v1 >> 5) + t1);
            v1 += (v0 + 0x9e3779b9) ^ ((v0 << 4) + t2) ^ ((v0 >> 5) + t3);
            v0 += (v1 + 0x3c6ef372) ^ ((v1 << 4) + t0) ^ ((v1 >> 5) + t1);
            v1 += (v0 + 0x3c6ef372) ^ ((v0 << 4) + t2) ^ ((v0 >> 5) + t3);
            v0 += (v1 + 0xdaa66d2b) ^ ((v1 << 4) + t0) ^ ((v1 >> 5) + t1);
            v1 += (v0 + 0xdaa66d2b) ^ ((v0 << 4) + t2) ^ ((v0 >> 5) + t3);
            v0 += (v1 + 0x78dde6e4) ^ ((v1 << 4) + t0) ^ ((v1 >> 5) + t1);
            v1 += (v0 + 0x78dde6e4) ^ ((v0 << 4) + t2) ^ ((v0 >> 5) + t3);
            v0 += (v1 + 0x1715609d) ^ ((v1 << 4) + t0) ^ ((v1 >> 5) + t1);
            v1 += (v0 + 0x1715609d) ^ ((v0 << 4) + t2) ^ ((v0 >> 5) + t3);
            v0 += (v1 + 0xb54cda56) ^ ((v1 << 4) + t0) ^ ((v1 >> 5) + t1);
            v1 += (v0 + 0xb54cda56) ^ ((v0 << 4) + t2) ^ ((v0 >> 5) + t3);
            v0 += (v1 + 0x5384540f) ^ ((v1 << 4) + t0) ^ ((v1 >> 5) + t1);
            v1 += (v0 + 0x5384540f) ^ ((v0 << 4) + t2) ^ ((v0 >> 5) + t3);
            v0 += (v1 + 0xf1bbcdc8) ^ ((v1 << 4) + t0) ^ ((v1 >> 5) + t1);
            v1 += (v0 + 0xf1bbcdc8) ^ ((v0 << 4) + t2) ^ ((v0 >> 5) + t3);
            v0 += (v1 + 0x8ff34781) ^ ((v1 << 4) + t0) ^ ((v1 >> 5) + t1);
            v1 += (v0 + 0x8ff34781) ^ ((v0 << 4) + t2) ^ ((v0 >> 5) + t3);
            v0 += (v1 + 0x2e2ac13a) ^ ((v1 << 4) + t0) ^ ((v1 >> 5) + t1);
            v1 += (v0 + 0x2e2ac13a) ^ ((v0 << 4) + t2) ^ ((v0 >> 5) + t3);
            v0 += (v1 + 0xcc623af3) ^ ((v1 << 4) + t0) ^ ((v1 >> 5) + t1);
            v1 += (v0 + 0xcc623af3) ^ ((v0 << 4) + t2) ^ ((v0 >> 5) + t3);
            v0 += (v1 + 0x6a99b4ac) ^ ((v1 << 4) + t0) ^ ((v1 >> 5) + t1);
            v1 += (v0 + 0x6a99b4ac) ^ ((v0 << 4) + t2) ^ ((v0 >> 5) + t3);
            v0 += (v1 + 0x08d12e65) ^ ((v1 << 4) + t0) ^ ((v1 >> 5) + t1);
            v1 += (v0 + 0x08d12e65) ^ ((v0 << 4) + t2) ^ ((v0 >> 5) + t3);
            v0 += (v1 + 0xa708a81e) ^ ((v1 << 4) + t0) ^ ((v1 >> 5) + t1);
            v1 += (v0 + 0xa708a81e) ^ ((v0 << 4) + t2) ^ ((v0 >> 5) + t3);
            v0 += (v1 + 0x454021d7) ^ ((v1 << 4) + t0) ^ ((v1 >> 5) + t1);
            v1 += (v0 + 0x454021d7) ^ ((v0 << 4) + t2) ^ ((v0 >> 5) + t3);
            v0 += (v1 + 0xe3779b90) ^ ((v1 << 4) + t0) ^ ((v1 >> 5) + t1);
            v1 += (v0 + 0xe3779b90) ^ ((v0 << 4) + t2) ^ ((v0 >> 5) + t3);
            iv1 = ((uint64_t)(v0) << 32 | (uint64_t)(v1));
        }
        iv1 = iv1 ^ iv2;
        iv2 = holder;
        (*((uint64_t *)(&ret_buffer[i]))) = htobe64(iv1);
    }
    (*out_buf_len) = ret_buf_len;
    return ret_buffer;
}

/*
 * 描述:用qqtea来解密
 * 参数key:长度必须为16
 * 参数out_buf_len:解密后的数据长度
 * 返回值:解密后的数据，使用qqtea_free来释放
 */
unsigned char *qqtea_decode(const unsigned char *key, const unsigned char *buffer, uint32_t len, uint32_t *out_buf_len)
{
    if (len < 16 || len % 8 != 0)
    {
        (*out_buf_len) = 0;
        return NULL;
    }
    unsigned char *ret_buffer = (unsigned char *)malloc(len);
    if (!ret_buffer)
    {
        (*out_buf_len) = 0;
        return NULL;
    }
    uint32_t t0 = be32toh(*((uint32_t *)&key[0]));
    uint32_t t1 = be32toh(*((uint32_t *)&key[4]));
    uint32_t t2 = be32toh(*((uint32_t *)&key[8]));
    uint32_t t3 = be32toh(*((uint32_t *)&key[12]));
    uint64_t iv1 = 0, iv2 = 0, holder = 0, tmp = 0;
    for (uint32_t i = 0; i < len; i += 8)
    {
        uint64_t block = be64toh(*((uint64_t *)&buffer[i]));
        {
            uint64_t n = block ^ iv2;
            uint32_t v0 = (uint32_t)(n >> 32);
            uint32_t v1 = (uint32_t)(n);
            v1 -= (v0 + 0xe3779b90) ^ ((v0 << 4) + t2) ^ ((v0 >> 5) + t3);
            v0 -= (v1 + 0xe3779b90) ^ ((v1 << 4) + t0) ^ ((v1 >> 5) + t1);
            v1 -= (v0 + 0x454021d7) ^ ((v0 << 4) + t2) ^ ((v0 >> 5) + t3);
            v0 -= (v1 + 0x454021d7) ^ ((v1 << 4) + t0) ^ ((v1 >> 5) + t1);
            v1 -= (v0 + 0xa708a81e) ^ ((v0 << 4) + t2) ^ ((v0 >> 5) + t3);
            v0 -= (v1 + 0xa708a81e) ^ ((v1 << 4) + t0) ^ ((v1 >> 5) + t1);
            v1 -= (v0 + 0x08d12e65) ^ ((v0 << 4) + t2) ^ ((v0 >> 5) + t3);
            v0 -= (v1 + 0x08d12e65) ^ ((v1 << 4) + t0) ^ ((v1 >> 5) + t1);
            v1 -= (v0 + 0x6a99b4ac) ^ ((v0 << 4) + t2) ^ ((v0 >> 5) + t3);
            v0 -= (v1 + 0x6a99b4ac) ^ ((v1 << 4) + t0) ^ ((v1 >> 5) + t1);
            v1 -= (v0 + 0xcc623af3) ^ ((v0 << 4) + t2) ^ ((v0 >> 5) + t3);
            v0 -= (v1 + 0xcc623af3) ^ ((v1 << 4) + t0) ^ ((v1 >> 5) + t1);
            v1 -= (v0 + 0x2e2ac13a) ^ ((v0 << 4) + t2) ^ ((v0 >> 5) + t3);
            v0 -= (v1 + 0x2e2ac13a) ^ ((v1 << 4) + t0) ^ ((v1 >> 5) + t1);
            v1 -= (v0 + 0x8ff34781) ^ ((v0 << 4) + t2) ^ ((v0 >> 5) + t3);
            v0 -= (v1 + 0x8ff34781) ^ ((v1 << 4) + t0) ^ ((v1 >> 5) + t1);
            v1 -= (v0 + 0xf1bbcdc8) ^ ((v0 << 4) + t2) ^ ((v0 >> 5) + t3);
            v0 -= (v1 + 0xf1bbcdc8) ^ ((v1 << 4) + t0) ^ ((v1 >> 5) + t1);
            v1 -= (v0 + 0x5384540f) ^ ((v0 << 4) + t2) ^ ((v0 >> 5) + t3);
            v0 -= (v1 + 0x5384540f) ^ ((v1 << 4) + t0) ^ ((v1 >> 5) + t1);
            v1 -= (v0 + 0xb54cda56) ^ ((v0 << 4) + t2) ^ ((v0 >> 5) + t3);
            v0 -= (v1 + 0xb54cda56) ^ ((v1 << 4) + t0) ^ ((v1 >> 5) + t1);
            v1 -= (v0 + 0x1715609d) ^ ((v0 << 4) + t2) ^ ((v0 >> 5) + t3);
            v0 -= (v1 + 0x1715609d) ^ ((v1 << 4) + t0) ^ ((v1 >> 5) + t1);
            v1 -= (v0 + 0x78dde6e4) ^ ((v0 << 4) + t2) ^ ((v0 >> 5) + t3);
            v0 -= (v1 + 0x78dde6e4) ^ ((v1 << 4) + t0) ^ ((v1 >> 5) + t1);
            v1 -= (v0 + 0xdaa66d2b) ^ ((v0 << 4) + t2) ^ ((v0 >> 5) + t3);
            v0 -= (v1 + 0xdaa66d2b) ^ ((v1 << 4) + t0) ^ ((v1 >> 5) + t1);
            v1 -= (v0 + 0x3c6ef372) ^ ((v0 << 4) + t2) ^ ((v0 >> 5) + t3);
            v0 -= (v1 + 0x3c6ef372) ^ ((v1 << 4) + t0) ^ ((v1 >> 5) + t1);
            v1 -= (v0 + 0x9e3779b9) ^ ((v0 << 4) + t2) ^ ((v0 >> 5) + t3);
            v0 -= (v1 + 0x9e3779b9) ^ ((v1 << 4) + t0) ^ ((v1 >> 5) + t1);
            tmp = ((uint64_t)(v0) << 32 | (uint64_t)(v1));
        }
        iv2 = tmp;
        holder = tmp ^ iv1;
        iv1 = block;
        (*((uint64_t *)(&ret_buffer[i]))) = htobe64(holder);
    }
    (*out_buf_len) = len - ((ret_buffer[0] & 7) + 3) - 7;
    unsigned char *ret_buffer2 = (unsigned char *)malloc(*out_buf_len);
    if (!ret_buffer2)
    {
        free(ret_buffer);
        (*out_buf_len) = 0;
        return NULL;
    }
    memcpy(ret_buffer2, ret_buffer + ((ret_buffer[0] & 7) + 3), (*out_buf_len));
    free(ret_buffer);
    return ret_buffer2;
}

/*
 * 描述:释放加解密函数返回指针指向的内存(空指针安全)
 */
void qqtea_free(unsigned char *buffer)
{
    free(buffer);
}