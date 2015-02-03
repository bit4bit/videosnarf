/*--------------------------------------------------------------------------------*
 *                                                                                *
 * This material is trade secret owned by imtelephone.com                         *
 * and is strictly confidential and shall remain as such.                         *
 *                                                                                *
 * Copyright © 2003-2004 imtelephone.com. All Rights Reserved. No part of         *
 * this material may be reproduced, stored in a retrieval system, or transmitted, *
 * in any form or by any means, including, but not limited to, photocopying,      *
 *  electronic, mechanical, recording, or otherwise, without the prior written    *
 * permission of imtelephone.com.                                                 *
 *                                                                                *
 * This material is subject to continuous developments and improvements. All      *
 * warranties implied or expressed, including but not limited to implied          *
 * warranties of merchantability, or fitness for purpose, are excluded.           *
 *                                                                                *
 *--------------------------------------------------------------------------------*
 *                                                                                *
 * support@imtelephone.com                                                        *
 *                                                                                *
 *--------------------------------------------------------------------------------*
 *
 *--------------------------------------------------------------------------------*
 *                            EasyG7231.h	                               	  *
 *                         ~~~~~~~~~~~~~~~~~~                                     *
 *--------------------------------------------------------------------------------*/


/* EasyG7231 API functions prototypes and constants */

#include "EasyG7231_macros.h"

extern CODER_HANDLE EasyG7231_init_encoder(bool bUseRate63 );
extern bool   EasyG7231_encoder(CODER_HANDLE hEncoder, short *speech, unsigned char *bitstream);
extern bool   EasyG7231_release_encoder(CODER_HANDLE hEncoder);

extern CODER_HANDLE EasyG7231_init_decoder(bool bUseRate64);
extern bool   EasyG7231_decoder(CODER_HANDLE hDecoder, unsigned char *bitstream, short *synth_short);
extern bool   EasyG7231_release_decoder(CODER_HANDLE hDecoder);
