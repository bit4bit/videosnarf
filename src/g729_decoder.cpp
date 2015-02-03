#include "stream.h"
#include "EasyG729A.h"

extern "C" {
	int initialize_g729_decoder(struct MediaStream *);
};
extern "C" {
	int decode_payload_g729(struct MediaStream *, u_char *, int);
};
extern "C" {
	int create_wav_header(FILE *, unsigned short, unsigned short, unsigned int, short);
};

int initialize_g729_decoder(struct MediaStream *currentMS){
	
	currentMS->hDecoder = EasyG729A_init_decoder();

	int return_wav = create_wav_header(currentMS->fp, 1, 16, 8000, 1);
    if(return_wav < 0){
    	printf("[-]Cannot write wav header file, wav file %s will be not be playable\n",currentMS->mediaFileName);
        return -1;
	}

	return 0;
}

int decode_payload_g729(struct MediaStream *currentMS, u_char *payload, int size_payload){


	unsigned char serial[L_G729A_FRAME_COMPRESSED];
    short synth[L_G729A_FRAME];

    int num_of_frame_compressed = size_payload / L_G729A_FRAME_COMPRESSED;

    int i = 0;
    for(i = 0; i < num_of_frame_compressed; i++){

    	memcpy(serial, payload + (i * L_G729A_FRAME_COMPRESSED), L_G729A_FRAME_COMPRESSED);
        EasyG729A_decoder(currentMS->hDecoder, serial, synth );

        size_t ret = fwrite(synth,sizeof(short),L_G729A_FRAME,currentMS->fp);
        if(ret < L_G729A_FRAME){
        	printf("[-]Error: Writing data to file %s:%s \n",currentMS->mediaFileName,strerror(errno));
            return -1;
        }
        memset(serial, '\0', sizeof(serial));
        memset(synth, '\0', sizeof(synth));
	}

	return 0;
}
