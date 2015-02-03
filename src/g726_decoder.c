#include "stream.h"
#include "EasyG726.h"


int initialize_g726_decoder(struct MediaStream *currentMS);
int decode_payload_g726(struct MediaStream *currentMS, u_char *payload, int size_payload, int sampleSize);

int initialize_g726_decoder(struct MediaStream *currentMS){

    currentMS->hDecoder = EasyG726_init_decoder();

    int return_wav = create_wav_header(currentMS->fp, 1, 16, 8000, 1);
    if(return_wav < 0){
        printf("[-]Cannot write wav header file, wav file %s will be not be playable\n",currentMS->mediaFileName);
        return -1;
    }

    return 0;
}

int decode_payload_g726(struct MediaStream *currentMS, u_char *payload, int size_payload, int sampleSize){


    unsigned char *serial;
    short *synth;
	short *synthPtr;
	unsigned char codeCur;

	serial = (unsigned char*)calloc(size_payload,sizeof(unsigned char));
	if(serial == NULL){
		printf("[-] Cannot allocate memory for serial buffer\n");
		return -1;
	}

	synth = (short*) calloc(size_payload * 2, sizeof(short));
	if(synth == NULL){
		printf("[-] Cannot allocate memory for synth buffer\n");
		return -1;
	}
	
	synthPtr = synth;
	int i = 0;
    for(i = 0;i < size_payload;i++){

		codeCur = (serial[i] & 0xF0) >> 4;
        EasyG726_decoder(currentMS->hDecoder, &codeCur, (synth+2*i), 3, sampleSize );

        codeCur = serial[i] & 0x0F;
        EasyG726_decoder(currentMS->hDecoder, &codeCur, (synth+2*i+1), 3, sampleSize );

    }

	size_t ret = fwrite(synthPtr,sizeof(short),(size_payload*2),currentMS->fp);
    if(ret < (size_payload*2)){
    	printf("[-]Error: Writing data to file %s:%s \n",currentMS->mediaFileName,strerror(errno));
        return -1;
    }
	
    return 0;
}
