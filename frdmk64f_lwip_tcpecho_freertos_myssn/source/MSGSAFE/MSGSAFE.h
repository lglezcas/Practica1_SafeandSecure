/*
 * MSGSAFE.h
 *
 *  Created on: 20 feb. 2021
 *      Author: Luis González
 */

#ifndef MSGSAFE_MSGSAFE_H_
#define MSGSAFE_MSGSAFE_H_

#include "MSGSAFE_def.h"
#include "MSGSAFE_cfg.h"

extern void aescrc_test_task(uint8_t *arg, size_t size);
extern uint8_t MSGSAFE_u8CheckCrc(uint8_t *arg, size_t size);
extern void MSGSAFE_u8AesDecrypt(uint8_t *arg, size_t size);

#endif /* MSGSAFE_MSGSAFE_H_ */
