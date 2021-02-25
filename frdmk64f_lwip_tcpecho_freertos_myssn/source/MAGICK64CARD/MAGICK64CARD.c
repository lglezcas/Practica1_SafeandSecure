/*
 * MAGICK64CARD.c
 *
 *  Created on: 20 feb. 2021
 *      Author: Luis González
 */

/* System headers */
#include "board.h"
/*Used headers*/
#include "MSGSAFE.h"
#include "fsl_debug_console.h"

/*Own headers*/
#include "MAGICK64CARD.h"
#include "MAGICK64CARD_cfg.h"

static void MAGICK64CARD_s_vCleanCrc(uint8_t *arg, size_t size)
{
	arg[size-1] = 0;
	arg[size-2] = 0;
	arg[size-3] = 0;
	arg[size-4] = 0;
}

static void __s_vCleanMsg(uint8_t *msg)
{
	uint8_t u8size = strlen(msg);

	for(uint8_t u8i = 0; u8i < u8size ; u8i++)
	{
		msg[u8i] = 0;
	}
}

typedef struct
{
	uint8_t stringmsg[255];
}MAGICK64CARD_s_tstMsg;
static void MAGICK64CARD_s_vApp(uint8_t *msg)
{
	uint8_t u8size = strlen(msg);
	MAGICK64CARD_s_tstMsg stStringMsgBuff[21] = MAGICK64CARD_MSG_CFG;
	uint8_t u8sizemsg = 0;
	uint8_t u8RandAnswer = 0;

	u8RandAnswer = (rand() % 20);

	if(msg[u8size-1]=='?')
	{
		__s_vCleanMsg(msg);
		u8sizemsg = strlen(stStringMsgBuff[u8RandAnswer].stringmsg);
		for(uint8_t u8i = 0; u8i < u8sizemsg ; u8i++)
		{
			msg[u8i] = stStringMsgBuff[u8RandAnswer].stringmsg[u8i];
		}
	}
	else
	{
		__s_vCleanMsg(msg);
		u8sizemsg = strlen(stStringMsgBuff[20].stringmsg);
		for(uint8_t u8i = 0; u8i < u8sizemsg ; u8i++)
		{
			msg[u8i] = stStringMsgBuff[20].stringmsg[u8i];
		}
	}
}

void MAGICK64CARD_vNewMsgRx(uint8_t *arg, size_t size, struct netconn *newconn)
{
	uint8_t padded_msg[512] = {0};
	uint8_t u8CrcCheck = CRC_NOT_OK;
	uint8_t u8SizeNoCrc = size-4;
	uint8_t u8SizeMsg = 0;

	memcpy(padded_msg, arg, size);


	u8CrcCheck = MSGSAFE_u8CheckCrc((uint8_t *)padded_msg,size);

	if(u8CrcCheck == CRC_OK)
	{
		MAGICK64CARD_s_vCleanCrc((uint8_t *)padded_msg,size);
		MSGSAFE_u8AesDecrypt((uint8_t *)padded_msg,u8SizeNoCrc);

		MAGICK64CARD_s_vApp((uint8_t *)padded_msg);

		u8SizeMsg = strlen(padded_msg);

		MSGSAFE_u8AesEncrypt((uint8_t *)padded_msg,u8SizeMsg);

		u8SizeMsg = strlen(padded_msg);

		MSGSAFE_vAddCrc((uint8_t *)padded_msg,u8SizeMsg);

		u8SizeMsg = strlen(padded_msg);

		netconn_write(newconn, padded_msg, u8SizeMsg, NETCONN_COPY);
	}
	else
	{
		PRINTF("ERROR: CRC Failed");
	}


	asm("nop");

}

