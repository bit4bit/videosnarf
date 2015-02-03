/*--------------------------------------------------------------------------------*
 *                                                                                *
 * This material is trade secret owned by imtelephone.com                         *
 * and is strictly confidential and shall remain as such.                         *
 *                                                                                *
 * Copyright © 2003-2006 imtelephone.com. All Rights Reserved. No part of          *
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
 *                            EasyG726.h                                          *
 *                         ~~~~~~~~~~~~~~~~~~                                     *
 *--------------------------------------------------------------------------------*/


/* EasyG726 API functions prototypes and constants */

#define  CODER_HANDLE  unsigned long

extern CODER_HANDLE EasyG726_init_encoder();
/*
	For in_coding:
			1		AUDIO_ENCODING_ULAW		 ISDN u-law 
			2		AUDIO_ENCODING_ALAW		 ISDN A-law 
			3		AUDIO_ENCODING_LINEAR	 PCM 2's-complement (0-center)
	For bitsPerSample
			2		16kbps
			3		24kbps
			4		32kbps
			5		40kbps
 */
extern int   EasyG726_encoder(CODER_HANDLE hEncoder, short *speech, unsigned char *bitstream, int in_coding, int bitsPerSample );
extern int   EasyG726_release_encoder(CODER_HANDLE hEncoder);

extern CODER_HANDLE EasyG726_init_decoder();
/*
	For out_coding:
			1		AUDIO_ENCODING_ULAW		 ISDN u-law 
			2		AUDIO_ENCODING_ALAW		 ISDN A-law 
			3		AUDIO_ENCODING_LINEAR	 PCM 2's-complement (0-center)
	For bitsPerSample
			2		16kbps
			3		24kbps
			4		32kbps
			5		40kbps
 */
extern int   EasyG726_decoder(CODER_HANDLE hDecoder, unsigned char *bitstream, short *speech, int out_coding, int bitsPerSample );
extern int   EasyG726_release_decoder(CODER_HANDLE hDecoder);

