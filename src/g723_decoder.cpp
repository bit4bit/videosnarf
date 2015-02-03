#include "stream.h"
#include "EasyG7231.h"

extern "C" {
	int initialize_g723_decoder(struct MediaStream *, int);
};
extern "C" {
	int decode_payload_g723(struct MediaStream *, u_char *, int ,int);
};
extern "C" {
	
	int create_wav_header(FILE *, unsigned short, unsigned short, unsigned int, short);
};

int initialize_g723_decoder(struct MediaStream *currentMS, int frameType){

	bool fType = true;
	if(frameType)
		fType = true;
	else if(!frameType)
		fType = false;

    currentMS->hDecoder = EasyG7231_init_decoder(fType);

    int return_wav = create_wav_header(currentMS->fp, 1, 16, 8000, 1);
    if(return_wav < 0){
        printf("[-]Cannot write wav header file, wav file %s will be not be playable\n",currentMS->mediaFileName);
        return -1;
    }

    return 0;
}

int decode_payload_g723(struct MediaStream *currentMS, u_char *payload, int size_payload,int frameType){

	int num_of_frame_compressed = 0;
	int frameCompressionValue = 0;

	if(frameType)
		frameCompressionValue = L_G7231_FRAME_COMPRESSED_63;
	else
		frameCompressionValue = L_G7231_FRAME_COMPRESSED_53;
	
	num_of_frame_compressed = size_payload / frameCompressionValue;

	unsigned char *serial;
	short           synth[L_G7231_FRAME] = {'\0'};

	serial = (unsigned char*) calloc(frameCompressionValue, sizeof(unsigned char));
	if(serial == NULL){
		printf("[-] Error allocating memory for serial buffer \n");
		return -1;
	}

    int i = 0;
    for(i = 0; i < num_of_frame_compressed; i++){

        memcpy(serial, payload + (i * frameCompressionValue), frameCompressionValue);
        EasyG7231_decoder(currentMS->hDecoder, serial, synth );

        size_t ret = fwrite(synth,sizeof(short),L_G7231_FRAME,currentMS->fp);
        if(ret < L_G7231_FRAME){
            printf("[-]Error: Writing data to file %s:%s \n",currentMS->mediaFileName,strerror(errno));
            return -1;
        }
        memset(serial, '\0', frameCompressionValue);
        memset(synth, '\0', sizeof(synth));
    }

    return 0;
}

