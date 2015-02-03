#define phtonl(p, v) \
        {                               \
        (p)[0] = (u_int8_t)((v) >> 24);   \
        (p)[1] = (u_int8_t)((v) >> 16);   \
        (p)[2] = (u_int8_t)((v) >> 8);    \
        (p)[3] = (u_int8_t)((v) >> 0);    \
        }

#define phtons(p, v) \
        {                               \
        ((u_int8_t*)(p))[0] = (u_int8_t)((v) >> 8); \
        ((u_int8_t*)(p))[1] = (u_int8_t)((v) >> 0); \
        }

struct AggregateNAL{

        u_char *buffer;
        int bufferLength;
        int dondistance;

        struct AggregateNAL *next;
};

struct naluHeader{
                unsigned forbidden:1;
                unsigned nri:2;
                unsigned type:5;
};

void bubblesortAggregateNALDON(struct AggregateNAL **);
void parseH264FUANAL(struct naluHeader *, u_char **, int *, int *, int *, int *);
void parseH264STAPANAL(u_char **,int, char *, FILE *, int *, int *);
void parseH264STAPBNAL(u_char **,int, char *, FILE *, int *, int *);
void parseH264MTAPNAL(u_char **, int, char *, FILE *, int *, int *, int);
