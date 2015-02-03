#include "stream.h"

#define X(a,b) b,
char *codecStrings[] = {
        CODEC_TABLE
};
#undef X

static struct MediaStream * findStream(char *, char *, int, int, struct sniff_rtp *, enum CODEC, char);
static struct MediaStream * addNewStream(char *, char *, int, int, struct sniff_rtp *, enum CODEC, char);
static int checkRTPStream(struct sniff_rtp *);
static int copyStreamValues(struct MediaStream **, char *,char *,int, int, struct sniff_rtp *, enum CODEC, char);
static void deleteStream(struct MediaStream *);

struct MediaStream *Head;
struct MediaStream *Tail;
int streamCount;
extern int checkParameterSets;
extern char *outputBaseFile;

struct MediaStream * streamHandler(char *srcIP, char *dstIP, int srcPort, int dstPort, struct sniff_rtp *rtp, enum CODEC codec, char codecType){

	struct MediaStream *currentMS = NULL;

	currentMS = findStream(srcIP, dstIP, srcPort, dstPort, rtp, codec, codecType);
	if(currentMS == NULL){

		int check = checkRTPStream(rtp);
		if(check == 1){
				
			currentMS = addNewStream(srcIP, dstIP, srcPort, dstPort, rtp, codec, codecType);
			if(currentMS == NULL){
				printf("[-]Cannot add new stream from %s(%d) to %s(%d)\n",srcIP, srcPort, dstIP, dstPort);
				return NULL;
			}
			printf("added new stream. :%s(%d) to %s(%d). codec is %02x\n", srcIP, srcPort, dstIP, dstPort, codecType);
			return currentMS;
		}
		
		//printf("[-]Identified packet is not a valid RTP stream. %s(%d) to %s(%d)\n", srcIP, srcPort, dstIP, dstPort);
		return NULL;
	}
	
	return currentMS;
}

static struct MediaStream * findStream(char *srcIP, char *dstIP, int srcPort, int dstPort, struct sniff_rtp *rtp, enum CODEC codec, char codecType){

	struct MediaStream *currentMS = Head;
	
	while(currentMS != NULL){

		if((!strcmp(currentMS->srcIP,srcIP)) && (!strcmp(currentMS->dstIP,dstIP)) && (currentMS->srcPort == srcPort) && ((currentMS->dstPort == dstPort)) && (currentMS->rtpPTR->payloadType == (rtp->payloadType & 0x7F)) && (currentMS->codecType == codecType) && (currentMS->codec == codec))
	     	{
#ifdef ARCH_X64
			if(currentMS->rtpPTR->ssrc == bswap_32(rtp->ssrc))
			{
				return currentMS;
			}
#else
			if(currentMS->rtpPTR->ssrc == ntohl(rtp->ssrc))
			{
				return currentMS;
			}
#endif
		}

		currentMS = currentMS -> next;
	}

	return NULL;
}
	

static struct MediaStream * addNewStream(char *srcIP, char *dstIP, int srcPort, int dstPort, struct sniff_rtp *rtp, enum CODEC codec, char codecType){

	if((Head == NULL) && (Tail == NULL)){

		/* Probably the first media stream */

		struct MediaStream *currentMediaStream = (struct MediaStream *) malloc(1 * sizeof(struct MediaStream));
		if(currentMediaStream == NULL){
			printf("[-]Not enough memory available for allocation: %s\n",strerror(errno));
			return NULL;
		}

		int copyreturn = copyStreamValues(&currentMediaStream,srcIP,dstIP,srcPort,dstPort,rtp,codec,codecType);
		if(copyreturn < 0){
			deleteStream(currentMediaStream);
			return NULL;
		}

		Head = Tail = currentMediaStream;

		return currentMediaStream;
	}
	else{
		struct MediaStream *currentMediaStream = (struct MediaStream *) malloc(1 * sizeof(struct MediaStream));
                if(currentMediaStream == NULL){
                        printf("[-]Not enough memory available for allocation: %s\n",strerror(errno));
                        return NULL;
                }

		int copyreturn = copyStreamValues(&currentMediaStream,srcIP,dstIP,srcPort,dstPort,rtp,codec,codecType);
		if(copyreturn < 0){
			deleteStream(currentMediaStream);
			return NULL;
		}
		
		Tail->next = currentMediaStream;
		Tail = currentMediaStream;

		return currentMediaStream;
	}
}

static int checkRTPStream(struct sniff_rtp *rtp){

#ifdef ARCH_X64
	
	if((bswap_16(rtp->sequence_no) <= 65535) && (bswap_32(rtp->timestamp) <= 4294967295) && (bswap_32(rtp->ssrc) <= 4294967295) && ((rtp->version & 0xC0) == 0x80))
	{
		return 1;
	}
#else

	if((ntohs(rtp->sequence_no) <= 65535) && (ntohl(rtp->timestamp) <= 4294967295) && (ntohl(rtp->ssrc) <= 4294967295) && ((rtp->version & 0XC0) == 0x80)){
		return 1;
	}

#endif
	return 0;
} 
	
int copyStreamValues(struct MediaStream **currentMediaStreamPtr, char *srcIP, char *dstIP, int srcPort, int dstPort, struct sniff_rtp *rtp, enum CODEC codec, char codecType){

	struct MediaStream *currentMediaStream = *currentMediaStreamPtr;
	unsigned int remLength = 0;
	
	strncpy(currentMediaStream->srcIP, srcIP, sizeof(currentMediaStream->srcIP)-1);
	strncpy(currentMediaStream->dstIP, dstIP, sizeof(currentMediaStream->dstIP)-1);
	
	currentMediaStream->srcPort = srcPort;
	currentMediaStream->dstPort = dstPort;
	currentMediaStream->rtpPTR = (struct sniff_rtp *) malloc(1 * sizeof(struct sniff_rtp));
	if(currentMediaStream->rtpPTR == NULL){
		printf("[-]Not enough memory available for allocation\n");
		return -1;
	}
	currentMediaStream->rtpPTR->payloadType = (rtp->payloadType & 0x7F);
#ifdef ARCH_X64
	currentMediaStream->rtpPTR->sequence_no = bswap_16(rtp->sequence_no);
#else
	currentMediaStream->rtpPTR->sequence_no = ntohs(rtp->sequence_no);
#endif
#ifdef ARCH_X64
	currentMediaStream->rtpPTR->timestamp = bswap_32(rtp->timestamp);
#else
	currentMediaStream->rtpPTR->timestamp = ntohl(rtp->timestamp);
#endif
#ifdef ARCH_X64
	currentMediaStream->rtpPTR->ssrc = bswap_32(rtp->ssrc);
#else
	currentMediaStream->rtpPTR->ssrc = ntohl(rtp->ssrc);
#endif
	currentMediaStream->previousSequenceNo = 0;
	
	streamCount += 1;
	currentMediaStream->streamNumber = streamCount;

	if(checkParameterSets == 1){
		currentMediaStream->receivedParameterSets = 0;
	}
	else{
		currentMediaStream->receivedParameterSets = 1;
	}

	char *codecStringValue = codecStrings[codec];
	if(outputBaseFile == NULL)
		remLength = (sizeof(currentMediaStream->mediaFileName) - 1) - strlen(codecStringValue);
	else
		remLength = (sizeof(currentMediaStream->mediaFileName) - 1) - strlen(outputBaseFile);

	memset(currentMediaStream->mediaFileName,'\0',sizeof(currentMediaStream->mediaFileName));
	if(outputBaseFile == NULL)
		strncpy(currentMediaStream->mediaFileName,codecStringValue,(sizeof(currentMediaStream->mediaFileName)-remLength));
	else
		strncpy(currentMediaStream->mediaFileName,outputBaseFile,(sizeof(currentMediaStream->mediaFileName)-remLength));

	char stringStreamNumber[6];  /* Hoping the number of streams don't exceed 99,999 */
	snprintf(stringStreamNumber, sizeof(stringStreamNumber), "%d", streamCount);

	int restLength = strlen("-media-.wav") + strlen(stringStreamNumber) + 1;

	//char tempString[restLength];
	char *tempString = (char *) calloc(restLength, sizeof(char));
	if(tempString == NULL){
		printf("[-]Not enough memory for allocation:%s\n",strerror(errno));
		return -1;
	}
	
	strcpy(tempString,"-media-");
	strcat(tempString,stringStreamNumber);
	
	switch(codec){
		
		case h264:
		strcat(tempString,".264");
		break;
		
		case g711alaw:
		case g711ulaw:
		case g722:
		case g729:
		case g723:
		default:
		strcat(tempString,".wav");
		break;
	}
	
	strncat(currentMediaStream->mediaFileName,tempString,remLength);

	currentMediaStream->fp = fopen(currentMediaStream->mediaFileName,"w+|b");
	if(currentMediaStream->fp == NULL){
		printf("[-]Cannot open file %s: %s\n", currentMediaStream->mediaFileName, strerror(errno));
		return -1;
	}

	currentMediaStream->codec = codec;
	currentMediaStream->codecType = codecType;
	currentMediaStream->count = 0;

	currentMediaStream->fuaStart = 0;
	currentMediaStream->next = NULL;
	
	return 0;
}	
			
static void deleteStream(struct MediaStream *currentMS){

	if(currentMS != NULL)
		free(currentMS);
}

void deleteAllStreams(){

	struct MediaStream *currentMS = Head;
	int streamCounter = 0;

	while(currentMS != NULL){

		if(currentMS->fp != NULL){
			
			streamCounter += 1;
			printf("[+]Stream saved to file %s\n",currentMS->mediaFileName);	
			fclose(currentMS->fp);
		}

		struct MediaStream *temp = currentMS->next;
		free(currentMS);
		
		currentMS = temp;
	}
	
	if(!streamCounter)
		printf("[-]No RTP media stream found\n");
	else
		printf("[+]Number of streams found are %d\n",streamCounter);
}	



