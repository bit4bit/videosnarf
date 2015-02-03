#ifndef STREAM_H
#define STREAM_H

#include "videosnarf.h"
#include "g722.h"

#ifdef ARCH_X64
#include "byteswap.h"
#endif

#define COG711ULAW	0X00
#define COG711ALAW	0x08
#define COG722		0x09
#define COG729		0x12
#define COG723		0x04
#define COG726		0x02

#define CODEC_TABLE	\
X(g711ulaw, "G711ULAW")	\
X(g711alaw, "G711ALAW")	\
X(g722, "G722")		\
X(g729, "G729")		\
X(g723, "G723")		\
X(g726, "G726")		\
X(h264, "H264")

#define  X(a,b) a,
enum CODEC {
	CODEC_TABLE
};
#undef X

struct MediaStream{

	char srcIP[16];
	char dstIP[16];
	unsigned int srcPort;
	unsigned int dstPort;
	struct sniff_rtp *rtpPTR;
	char mediaFileName[256]; 	/* Example format: G711ULAW-media-1.wav */
	FILE *fp;
	int streamNumber;		/* RTP stream number */
	enum CODEC codec;		/* X Macro which returns the string equivalent of the codec */
	char codecType;			/* Codec type */
	int count;			/* Number of packets of this stream */

	u_short previousSequenceNo;
	/* G722 variables */
        g722_decode_state_t dec_state;

	/* H264 Variable */
	int fuaStart;
	int receivedParameterSets;

	/* G729/G723.1 Variable */
	unsigned long hDecoder;

	struct MediaStream *next;
};


struct MediaStream * streamHandler(char *, char *, int, int, struct sniff_rtp *, enum CODEC, char);
void deleteAllStreams();
extern int initialize_g729_decoder(struct MediaStream *currentMS);
extern int decode_payload_g729(struct MediaStream *currentMS, u_char *payload, int size_payload);
//extern int initialize_g726_decoder(struct MediaStream *currentMS);
//extern int decode_payload_g726(struct MediaStream *currentMS, u_char *payload, int size_payload, int sampleSize);
//int create_wav_header_cpp(FILE *fp, unsigned short, unsigned short, unsigned int, short);
#endif
