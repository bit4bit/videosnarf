#include "videosnarf.h"
#include "version.h"

static void show_help();


static void show_help(){

	printf("Usage: videosnarf [-i input pcap file] [-f filter expression] \n");
	printf("-i <input pcap file> (Mandatory) input pcap file\n");
	printf("-o <output file> (Optional) output base name file\n"); 
	printf("-f <filter expression> (Optional) pcap filter expression\n");
	printf("-k <g726 sample size> (Optional) G726 sameple size\n");

	printf("Note: sample size could be either 2, 3, 4, 5 bits for 16,24,32 and 40 kbits/s. The default Kbit/s will be 32 \n");
	printf("Note: If there are 802.1Q headers in the RTP packet capture, please don't set the filter expression \n");
	
	printf("Example Usage:\n");
	printf("videosnarf -i inputfile.pcap\n");
	printf("videosnarf -i inputfile.pcap -f \"udp dst port 25001\" \n");
	
}
	
extern char *inputPcapFile;
extern char *outputBaseFile;
extern char *filterExpression;
extern int userFilterExpressionSet;
extern int userH264PTSet;
extern int userH264PayloadType;
extern int checkParameterSets;
extern int g726SampleSize;

int main(int argc, char **argv){

	inputPcapFile = NULL;
	outputBaseFile = NULL;
	filterExpression = NULL;
	userFilterExpressionSet = 0;
	checkParameterSets = 0;	
	g726SampleSize = 4;		/* Default kbit/s set to 32, so the samplesize is 4 bits */
	int inputFileSet = 0;
	int opt = 0;

	printf("Starting videosnarf %d.%d\n",MAJOR_VERSION,MINOR_VERSION);

	while((opt = getopt(argc,argv,"i:o:f:p:k:ch")) != -1){

		switch(opt){
		
			case 'i':
				inputFileSet = 1;
				inputPcapFile = (char *)calloc(strlen(optarg) + 1, sizeof(char));
				if(inputPcapFile == NULL){
					printf("Not enough memory for allocation:%s\n",strerror(errno));
					exit(1);
				}
				strncpy(inputPcapFile,optarg,strlen(optarg));
				break;
			
			case 'o':
				outputBaseFile = (char *)calloc(strlen(optarg) + 1, sizeof(char));
				if(outputBaseFile == NULL)
				{
					printf("Not enough memory for allocation:%s\n",strerror(errno));
					exit(1);
				}
				strncpy(outputBaseFile,optarg,strlen(optarg));
				break;
			
			case 'f':
				userFilterExpressionSet = 1;
				filterExpression = (char *)calloc(strlen(optarg) + 1, sizeof(char));
				if(filterExpression == NULL){
					printf("Not enough memory for allocation:%s\n",strerror(errno));
                                        exit(1);
                                }
				strncpy(filterExpression,optarg,strlen(optarg));
				break;

			case 'p':
				/* Dynamic H264 Payload Type variable */
				break;

			case 'k':
				g726SampleSize = atoi(optarg);
				if(g726SampleSize < 1 && g726SampleSize > 5){
					printf("G726 sample size format not supported. Check usage or help \n");
					exit(1);
				}
				break;

			case 'c':
				/* Starts saving the h264 video stream, after receiving picture parameter and sequence parameter sets */
				checkParameterSets = 1;
				break;

			case 'h':
				show_help();
				return 0;
				break;	
		}
	}

	if(inputFileSet != 1){
		show_help();
		return 0;
	}

	printf("[+]Starting to snarf the media packets \n");
	mediasnarfStart();

	mediasnarfStop();
	printf("[+]Snarfing Completed\n");

	return 0;
}
