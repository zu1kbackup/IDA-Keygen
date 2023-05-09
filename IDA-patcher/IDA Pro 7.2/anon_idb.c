#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

typedef unsigned char u8;
#include "../anon_idb.h"

#define BUFSZ 0x1000

// for IDA versions v5.x patch libida.so
// 0010551B: 85 31
// so it will accept IDB databases created with a different key

u8 Patterns[] = {
 11, 0, 0, 5, 0, 0x53, 0, 0, 0, 0, 0xa0, 0,
 15, 0, 0, 9, 0, 0x53, 0, 0, 0, 0, 0, 0, 0, 0, 0xa0, 0,
 10, 0, 0, 0x3d, 0x53, 0, 0, 0, 0, 0xa0, 0,
 0
};

u8            buf[BUFSZ];

int
binsearch( int f, u8 * pat, int patlen, char *pat_desc )
{
  u8            b;
  int           i, l, pos, addr, off, found;

  addr = off = 0;
  lseek( f, 0, SEEK_SET );
  while( read( f, buf + off, BUFSZ - off ) > 0 )
  {
    for( pos = 0; pos < BUFSZ - patlen; pos++ )
    {
      found = 1;
      for( i = 0; i < patlen; i++ )
      {

	b = buf[pos + i];
	if( b != pat[i] )
	{
	  found = 0;
	  break;
	}
      }
      if( found )
	break;
    }
    if( found )
    {
      printf( "%s at address 0x%x\n", pat_desc, addr + pos );
      memmove( buf, buf + pos, BUFSZ - pos );
      break;
    }
    else
    {
      off = patlen;
      memmove( buf, buf + BUFSZ - off, off );
      addr += BUFSZ - off;
    }
  }
  if( found )
  {
    l = read( f, buf + BUFSZ - pos, pos );
    l += BUFSZ - pos;
    lseek( f, -l, SEEK_CUR );
  }
  return found;
}

int
main( int argc, char *argv[] )
{
  int           len, fd, patch = 0;
  u8	       *pat;
  char         *fname;

  if( argc <= 1 )
  {
    printf( "Usage: ida_database.idb\n" );
    return -1;
  }
  fname = strdup( argv[1] );
  fd = open( fname, O_RDWR );
  if( fd == -1 )
  {
    printf( "%s - File open error\n", fname );
    return -1;
  }
  pat = Patterns;
  while( 1 )
  {
    if( ( len = *pat++ ) == 0 )
      break;
    if( binsearch( fd, pat, len, "IDB license" ) )
    {
      memcpy( buf + len, hexData, sizeof( hexData ) );
      write( fd, buf, len + sizeof( hexData ) );
      // disable CRC32 check
      memset( buf, 0, 4 );
      lseek( fd, 0x24, SEEK_SET );
      write( fd, buf, 4 );
      printf( "%s - IDB license patched!\n", fname );
      patch = 1;
      break;
    }
    pat += len;
  }
  if( !patch )
  {
    printf( "%s - IDB license can't be patched!\n", fname );
    printf( "If possible re-save the IDB as "
	"'stored' instead of 'deflated' and try again\n" );
  }
  close( fd );
  return 0;
}
