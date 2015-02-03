#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <strings.h>
#include <errno.h>
#include <netinet/in.h>
#include "vsh264.h"

/* preform a bubble sort on the linked list, reference happycodings.com */
void bubblesortAggregateNALDON(struct AggregateNAL** head) {

 struct AggregateNAL *a = NULL;
 struct AggregateNAL *b = NULL;
 struct AggregateNAL *c = NULL;
 struct AggregateNAL *e = NULL;
 struct AggregateNAL *tmp = NULL;

 /*
 // the `c' node precedes the `a' and `e' node
 // pointing up the node to which the comparisons
 // are being made.
 */

 while(e != (*head)->next) {
 c = a = *head;
 b = a->next;
  while(a != e) {
   if(a->dondistance > b->dondistance) {
    if(a == *head) {
     tmp = b -> next;
     b->next = a;
     a->next = tmp;
     *head = b;
     c = b;
    } else {
     tmp = b->next;
     b->next = a;
     a->next = tmp;
     c->next = b;
     c = b;
    }
   } else {
    c = a;
    a = a->next;
   }
   b = a->next;
   if(b == e)
    e = a;
  }
 }
}

void parseH264MTAPNAL(u_char **value, int packetDataLength, char *file, FILE *fp, int *writeNALPrefixCode, int *writePacket, int type){

	int pdon = 0;
        ++(*value);
        int DONB = 0;
        memcpy(&DONB,*value,2);
        DONB = ntohs(DONB);
        *value += 2;
        int nalusize = 0;
        int totalnalusize = 0;
        memcpy(&nalusize,*value,2);
        nalusize = ntohs(nalusize);
	char pd[4] = { '\0' };

	*writeNALPrefixCode = 0;
	*writePacket = 0;

        if(nalusize != 0){
        	*value += 2;
        }
        else{
        	return;
        }

        int DOND = 0;
        memcpy(&DOND,*value,1);
        ++(*value);

        /* Skipping the timestamp offset */
	if(type == 16){
        	*value += 2;
	}
	else if(type == 24){
		*value += 3;
	}

	int bytes = 0;
	if(type == 16){
        	bytes = packetDataLength - 8;
	}
	else if(type == 24){
		bytes = packetDataLength - 9;
	}
		
        /* 8/9 bytes, 1st byte is NAL HDR(MTAP16), next 2 bytes are DONB, next 2 bytes are NALU size, next 1 byte is DOND and last 2/3 bytes are TS offset */

        struct AggregateNAL *firstMTAP = NULL;
        struct AggregateNAL *previousMTAP = NULL;

	while(totalnalusize < bytes){

       		totalnalusize += nalusize;

                struct AggregateNAL *mtap = NULL;

                if(firstMTAP == NULL){

                	mtap = (struct AggregateNAL *) calloc(1,sizeof(struct AggregateNAL));
                        if(mtap == NULL){
                        	fprintf(stderr,"[-]Error: Allocating memory for stapb NAL unit\n");
                                
                                return;
                        }
                        mtap->bufferLength = 0;
                        mtap->dondistance = 0;
                        mtap->next = NULL;
                        firstMTAP = mtap;
                        previousMTAP = mtap;
                }
                else{
                	mtap = (struct AggregateNAL *) calloc(1,sizeof(struct AggregateNAL));
                        if(mtap == NULL){
                        	fprintf(stderr,"[-]Error: Allocating memory for stapb NAL unit\n");
                                return;
                        }
                        mtap->bufferLength = 0;
                        mtap->dondistance = 0;
                        mtap->next = NULL;
                        previousMTAP->next = mtap;
                        previousMTAP = mtap;
                }
		mtap->buffer = (u_char *) calloc(nalusize,sizeof(u_char));
                if(mtap->buffer == NULL){
                	fprintf(stderr,"[-]Error: Allocating memory for stapb buffer\n");
			return;
                }
                memcpy(mtap->buffer,*value,nalusize);
                mtap->bufferLength = nalusize;
                int don = (DONB + DOND) % 65536;
                if(don > pdon)
                	mtap->dondistance = don - pdon;
                else
                	mtap->dondistance = 65535 - pdon + don + 1;

                *value += nalusize;

                if(totalnalusize < bytes){

                	memcpy(&nalusize,*value,2);
                        nalusize = ntohs(nalusize);
                        if(nalusize != 0){
                        	*value += 2;
                        }
                        else{
                        	break;
                        }
                        bytes =- 2;
                        memcpy(&DOND,*value,1);
                        *value += 1;
                        bytes =- 1;
                        /* Skipping 2/3 byte TS offset */
			if(type == 16){
                        	*value += 2;
                        	bytes =- 2;
			}
			else if(type == 24){
				*value += 3;
				bytes =- 3;
			}
               } 
	}

	struct AggregateNAL *currentMTAP = firstMTAP;
	bubblesortAggregateNALDON(&currentMTAP);
        while(currentMTAP != NULL){

        	phtonl(pd,0x00000001);
                fwrite(pd,1,4,fp);

                int ret = fwrite(currentMTAP->buffer, sizeof(u_char), currentMTAP->bufferLength, fp);
                if(ret < currentMTAP->bufferLength){

                	printf("[-]Error: Writing data to file %s:%s \n",file,strerror(errno));
                        return;
                }
                free(currentMTAP->buffer);
                struct AggregateNAL* lastMTAP = currentMTAP;
                currentMTAP = currentMTAP->next;
                free(lastMTAP);
       }
}

void parseH264STAPBNAL(u_char **value, int packetDataLength, char *file, FILE *fp, int *writeNALPrefixCode, int *writePacket){

	++(*value);
        int initialDON = 0;
        memcpy(&initialDON,*value,2);
        initialDON = ntohs(initialDON);
        *value += 2;
        int nalusize = 0;
        int totalnalusize = 0;
        memcpy(&nalusize,*value,2);
        nalusize = ntohs(nalusize);
        //totalnalusize = nalusize;
        int pdon = 0;
	char pd[4] = { '\0' };

	*writeNALPrefixCode = 0;
	*writePacket = 0;

        struct AggregateNAL *firstSTAPB = NULL;
        struct AggregateNAL *previousSTAPB = NULL;

        int bytes = packetDataLength - 5;
        /* 5, first byte is the size of STAP-A NAL HDR , second 2 bytes are the DON, last 2 bytes are NALU size*/

        if(nalusize != 0){
	        *value += 2;
        }
        else{
        	return;
        }

	while(totalnalusize < bytes){

		totalnalusize = totalnalusize + nalusize;

                struct AggregateNAL *stapb = NULL;

                if(firstSTAPB == NULL){

                	stapb = (struct AggregateNAL *) calloc(1,sizeof(struct AggregateNAL));
                        if(stapb == NULL){
                        	fprintf(stderr,"[-]Error: Allocating memory for stapb NAL unit\n");
                                return;
                        }
                        stapb->bufferLength = 0;
                        stapb->dondistance = 0;
                        stapb->next = NULL;
                        firstSTAPB = stapb;
                        previousSTAPB = stapb;
                }
                else{
                	stapb = (struct AggregateNAL *) calloc(1,sizeof(struct AggregateNAL));
                        if(stapb == NULL){
                        	fprintf(stderr,"[-]Error: Allocating memory for stapb NAL unit\n");
                                return;
                        }
                        stapb->bufferLength = 0;
                        stapb->dondistance = 0;
                        stapb->next = NULL;
                        previousSTAPB->next = stapb;
                        previousSTAPB = stapb;
		}

		stapb->buffer = (u_char *) calloc(nalusize,sizeof(u_char));
               	if(stapb->buffer == NULL){
                       	fprintf(stderr,"[-]Error: Allocating memory for stapb buffer\n");
			return;
                }
                memcpy(stapb->buffer,*value,nalusize);
                stapb->bufferLength = nalusize;
                if(initialDON > pdon)
                       	stapb->dondistance = initialDON - pdon;
                else
                       	stapb->dondistance = 65535 - pdon + initialDON + 1;		

		*value = *value + nalusize;

                nalusize = 0;
                if(totalnalusize < bytes){
                	memcpy(&nalusize,*value,2);
                        nalusize = ntohs(nalusize);
                        bytes = bytes - 2;
                        initialDON += 1 % 65536;
                }

                if(nalusize != 0){
                	*value = *value + 2;
                }
                else{
                	break;
               	} 
	}

        struct AggregateNAL *currentSTAPB = firstSTAPB;
	bubblesortAggregateNALDON(&currentSTAPB);
        while(currentSTAPB != NULL){

                phtonl(pd,0x00000001);
                fwrite(pd,1,4,fp);
		int ret = fwrite(currentSTAPB->buffer, sizeof(u_char), currentSTAPB->bufferLength, fp);
                if(ret < currentSTAPB->bufferLength){

	                printf("[-]Error: Writing data to file %s:%s \n",file,strerror(errno));
                        return;
                }
                free(currentSTAPB->buffer);
                struct AggregateNAL* lastSTAPB = currentSTAPB;
                currentSTAPB = currentSTAPB->next;
                free(lastSTAPB);
	}
}


void parseH264STAPANAL(u_char **value, int packetDataLength, char *file, FILE *fp, int *writeNALPrefixCode, int *writePacket){

	++(*value);
	int nalusize = 0;
        int totalnalusize = 0;
        memcpy(&nalusize,*value,2);
        nalusize = ntohs(nalusize);
        //totalnalusize = nalusize;
	char pd[4] = { '\0' };

	int bytes = packetDataLength - 3;
        /* 3 bytes are, first byte is the size of STAP-A NAL HDR and last 2 bytes are the NALU Size*/

	*writeNALPrefixCode = 0;
	*writePacket = 0;

	if(nalusize != 0){
        	*value += 2;
        }
        else{
        	return;
        }

	while(totalnalusize < bytes){

        	totalnalusize = totalnalusize + nalusize;

                phtonl(pd,0x00000001);
                fwrite(pd,1,4,fp);

                int ret = fwrite(*value, sizeof(u_char), nalusize, fp);
                if(ret < nalusize){

			printf("[-]Error: Writing data to file %s:%s \n",file,strerror(errno));
                        return;
                }

                *value = *value + nalusize;

		nalusize = 0;
                if(totalnalusize < bytes){
                	memcpy(&nalusize,*value,2);
                        nalusize = ntohs(nalusize);
                        bytes = bytes - 2;
                }

		if(nalusize != 0){
                	*value = *value + 2;
                }
                else{
                	break;
                }
	}
}

void parseH264FUANAL(struct naluHeader *naluHeaderValue, u_char **value, int *offset, int *writeNALPrefixCode, int *writePacket, int *fua_start){

	struct fuaHeader{
                unsigned start:1;
                unsigned end:1;
                unsigned reserved:1;
                unsigned type:5;
        };


	++(*value);
        ++(*offset);
	struct fuaHeader fuaHeaderValue;
        fuaHeaderValue.start = (**value & 0x80) >> 7;
        fuaHeaderValue.end = (**value & 0x40) >> 6;
        fuaHeaderValue.reserved = (**value & 0x20) >> 5;
        fuaHeaderValue.type = (**value) & 0x1F;

        if(fuaHeaderValue.start){

		/* Start of fragmented NAL unit */

                unsigned char naluHeaderValue1;

                naluHeaderValue1 = naluHeaderValue->forbidden << 7;
                naluHeaderValue1 |= naluHeaderValue->nri << 5;
                naluHeaderValue1 |= fuaHeaderValue.type;

                memcpy(*value,&naluHeaderValue1,1);

                *fua_start = 1;

	}
        else if((!fuaHeaderValue.start) && (*fua_start == 1)){

        	/* Subsequent NAL fragments */

                ++(*value);
                ++(*offset);
                *writeNALPrefixCode = 0;

                if(fuaHeaderValue.end){
                	*fua_start = 0;
                }
	}
        else{
		*writeNALPrefixCode = 0;
		*writePacket = 0;
	}
}

