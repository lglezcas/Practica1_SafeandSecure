/*
 * MSGSAFE.c
 *
 *  Created on: 20 feb. 2021
 *      Author: Luis González
 */
/* System headers */
#include "board.h"

/* Used headers */
#include "aes.h"
#include "fsl_crc.h"
#include "fsl_debug_console.h"

/* Own headers */
#include "MSGSAFE.h"


/*!
 * @brief Init for CRC-32.
 * @details Init CRC peripheral module for CRC-32 protocol.
 *          width=32 poly=0x04c11db7 init=0xffffffff refin=true refout=true xorout=0xffffffff check=0xcbf43926
 *          name="CRC-32"
 *          http://reveng.sourceforge.net/crc-catalogue/
 */
static void InitCrc32(CRC_Type *base, uint32_t seed)
{
    crc_config_t config;

    config.polynomial         = 0x04C11DB7U;
//    config.polynomial         = 0xEDB88320;
    config.seed               = seed;
    config.reflectIn          = true;
    config.reflectOut         = true;
    config.complementChecksum = true;
    config.crcBits            = kCrcBits32;
    config.crcResult          = kCrcFinalChecksum;

    CRC_Init(base, &config);
}

void aescrc_test_task(uint8_t *arg, size_t size)
{

	uint8_t test_string[] = {"01234567890123456789"};
	/* AES data */
	uint8_t key[] = { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06 };
	uint8_t iv[]  = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
	struct AES_ctx ctx;
	size_t test_string_len, padded_len;
	uint8_t padded_msg[512] = {0};
	uint8_t message[512] = {0};
	/* CRC data */
	CRC_Type *base = CRC0;
	uint32_t checksum32;
	uint8_t CRC_bytes[4] = {0};


	PRINTF("AES and CRC test task\r\n");

	PRINTF("\nTesting AES128\r\n\n");
	/* Init the AES context structure */
	AES_init_ctx_iv(&ctx, key, iv);

	/* To encrypt an array its lenght must be a multiple of 16 so we add zeros */
	test_string_len = strlen(test_string);
	padded_len = test_string_len + (16 - (test_string_len%16) );
	memcpy(padded_msg, test_string, test_string_len);

	test_string_len = size;
	padded_len = test_string_len-4 + (16 - ((test_string_len-4)%16) );
	memcpy(padded_msg, arg, test_string_len);

	CRC_bytes[3] = padded_msg[test_string_len-1];
	CRC_bytes[2] = padded_msg[test_string_len-2];
	CRC_bytes[1] = padded_msg[test_string_len-3];
	CRC_bytes[0] = padded_msg[test_string_len-4];

	padded_msg[test_string_len-4] = 0;
	padded_msg[test_string_len-3] = 0;
	padded_msg[test_string_len-2] = 0;
	padded_msg[test_string_len-1] = 0;

	InitCrc32(base, 0xFFFFFFFFU);
	CRC_WriteData(base, (uint8_t *)&padded_msg[0], size-4);
	checksum32 = CRC_Get32bitResult(base);

	PRINTF("CRC-32: 0x%08x\r\n", checksum32);

	AES_CBC_decrypt_buffer(&ctx, padded_msg, size-4);

	PRINTF("NO encrypted Message: ");
	for(int i=0; i<padded_len; i++) {
		PRINTF("0x%02x,", padded_msg[i]);
	}
	PRINTF("\r\n");
}

uint8_t MSGSAFE_u8CheckCrc(uint8_t *arg, size_t size)
{
	uint8_t u8CrcResult = CRC_NOT_OK;
	uint8_t padded_msg[512] = {0};
	CRC_Type *base = CRC0;
	uint32_t checksum32;
	uint32_t u32CrcReceived = 0;

	memcpy(padded_msg, arg, size);

	u32CrcReceived = ((padded_msg[size-4])		&0xFF		)|
					 ((padded_msg[size-3]<<8)	&0xFF00 	)|
					 ((padded_msg[size-2]<<16)	&0xFF0000 	)|
					 ((padded_msg[size-1]<<24)	&0xFF000000 );

	InitCrc32(base, MSGSAFE_CRC_SEED);
	CRC_WriteData(base, (uint8_t *)&padded_msg[0], size-4);
	checksum32 = CRC_Get32bitResult(base);

	if(checksum32 == u32CrcReceived)
	{
		u8CrcResult = CRC_OK;
	}
	else
	{
		/*Nothing to do*/
	}

	PRINTF("CRC-32 OK: 0x%08x\r\n", checksum32);
	return u8CrcResult;
}

void MSGSAFE_u8AesDecrypt(uint8_t *arg, size_t size)
{
	uint8_t key[] = MSGSAFE_AES_KEY;
	uint8_t iv[]  = MSGSAFE_AES_IV;
	struct AES_ctx ctx;

	AES_init_ctx_iv(&ctx, key, iv);

	AES_CBC_decrypt_buffer(&ctx, arg, size);
}

void MSGSAFE_u8AesEncrypt(uint8_t *arg, size_t size)
{
	uint8_t key[] = MSGSAFE_AES_KEY;
	uint8_t iv[]  = MSGSAFE_AES_IV;
	size_t padded_len = 0;
	struct AES_ctx ctx;

	AES_init_ctx_iv(&ctx, key, iv);

	AES_CBC_encrypt_buffer(&ctx, arg, size);
}

void MSGSAFE_vAddCrc(uint8_t *arg, size_t size)
{
	uint8_t u8CrcResult = CRC_NOT_OK;
	CRC_Type *base = CRC0;
	uint32_t checksum32;
	uint32_t u32CrcReceived = 0;


	InitCrc32(base, MSGSAFE_CRC_SEED);
	CRC_WriteData(base, (uint8_t *)&arg[0], size);
	checksum32 = CRC_Get32bitResult(base);
	PRINTF("CRC-32 OK: 0x%08x\r\n", checksum32);

	arg[size+3] = (checksum32 & 0xFF000000) >> 24;
	arg[size+2] = (checksum32 & 0x00FF0000) >> 16;
	arg[size+1] = (checksum32 & 0x0000FF00) >> 8;
	arg[size] = (checksum32 & 0x000000FF);
}
