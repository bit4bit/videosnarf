#include "stream.h"
#include "typedef.h"
#include "codecParameters.h"

#include "bcg729/decoder.h"

#define L_FRAME_COMPRESSED 10

extern int create_wav_header(FILE *, unsigned short, unsigned short, unsigned int, short);

int initialize_g729_decoder(struct MediaStream *currentMS){
	currentMS->hDecoder = (unsigned long)initBcg729DecoderChannel();
	
	int return_wav = create_wav_header(currentMS->fp, 1, 16, 8000, 1);
	if(return_wav < 0){
	  printf("[-]Cannot write wav header file, wav file %s will be not be playable\n",currentMS->mediaFileName);
	  return -1;
	}

	return 0;
}

int decode_payload_g729(struct MediaStream *currentMS, u_char *payload, int size_payload){
  bcg729DecoderChannelContextStruct *decoder = (bcg729DecoderChannelContextStruct *)currentMS->hDecoder;

  unsigned char serial[L_FRAME_COMPRESSED];
  short synth[L_FRAME];

  int num_of_frame_compressed = size_payload / L_FRAME_COMPRESSED;

  int i = 0;
  for(i = 0; i < num_of_frame_compressed; i++){
    memcpy(serial, payload + (i * L_FRAME_COMPRESSED), L_FRAME_COMPRESSED);
    bcg729Decoder(decoder, serial, 0, synth);

    size_t ret = fwrite(synth,sizeof(short),L_FRAME,currentMS->fp);
    if(ret < L_FRAME){
      printf("[-]Error: Writing data to file %s:%s \n",currentMS->mediaFileName,strerror(errno));
      return -1;
    }
    memset(serial, '\0', sizeof(serial));
    memset(synth, '\0', sizeof(synth));
  }

  return 0;
}
