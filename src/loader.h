typedef struct {
    int len;
    char val [ ];
} RESOURCE;

typedef void ( * AGENT_SETUP ) ( char * data, int len );

#define GET_RESOURCE(x) ( char * ) &x;

LPVOID allocate_memory ( size_t, DWORD );