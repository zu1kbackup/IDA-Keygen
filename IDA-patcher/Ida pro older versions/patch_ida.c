#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <dirent.h>
#include <stdint.h>
#include <errno.h>

#ifndef _MY_Uxx
#define _MY_Uxx
typedef uint8_t u8;
typedef uint16_t u16;
typedef uint32_t u32;
typedef uint64_t u64;
#endif

u8            mod_rsa[] = {
  0xed, 0xfd, 0x42, 0x5c, 0xf9, 0x78, 0x54, 0x6e,
  0x89, 0x11, 0x22, 0x58, 0x84, 0x43, 0x6c, 0x57,
};

u8            mod_new[] = {
  0xed, 0xfd, 0x42, 0xcb, 0xf9, 0x78, 0x54, 0x6e,
  0x89, 0x11, 0x22, 0x58, 0x84, 0x43, 0x6c, 0x57,
};

#define PAT_LEN (sizeof(mod_rsa))

#define BUFSIZE 0x4000
u8            buf[BUFSIZE];

int
patch_file( char *fname )
{
  FILE         *fl;
  u32          *w1, *w2, *wb, addr, offset, magic;
  int           i, l, wl, found;

  if( ( fl = fopen( fname, "rb" ) ) == NULL )
  {
    fprintf( stderr, "Cannot open file %s: %s\n", fname, strerror( errno ) );
    return -1;
  }
  fread( &magic, 1, 4, fl );
  fclose( fl );
  // check file magic == MZ || ELF || arch
  if( ( magic & 0xffff ) != 0x5a4d && magic != 0x464c457f
      && magic != 0x72613C21 )
    return -2;
  if( ( fl = fopen( fname, "r+b" ) ) == NULL )
  {
    fprintf( stderr, "Cannot write to file %s: %s\n",
	fname, strerror( errno ) );
    return -3;
  }
  printf( "- Parsing file %s\n", fname );
  found = 0;
  addr = 0;
  offset = 0;
  while( ( l = fread( buf + offset, 1, BUFSIZE - offset, fl ) ) > 0 )
  {
    w1 = ( u32 * ) mod_rsa;
    w2 = ( u32 * ) mod_new;
    wb = ( u32 * ) buf;
    wl = ( l + offset - PAT_LEN ) / sizeof( u32 );
    for( i = 0; i < wl; i++ )
    {
      if( *wb == *w1 )
      {
	if( *( wb + 1 ) == *( w1 + 1 ) && *( wb + 2 ) == *( w1 + 2 )
	    && *( wb + 3 ) == *( w1 + 3 ) )
	{
	  printf( "...RSA-1024 module found at address %x\n", addr );
	  printf( "...switching to new RSA-1024 module\n" );
	  *wb = *w2;
	  found = 1;
	  break;
	}
      }
      else if( *wb == *w2 )
      {
	if( *( wb + 1 ) == *( w2 + 1 ) && *( wb + 2 ) == *( w2 + 2 )
	    && *( wb + 3 ) == *( w2 + 3 ) )
	{
	  printf( "...RSA-1024 new module found at address 0x%x\n", addr );
	  printf( "...switching back to original RSA-1024 module\n" );
	  *wb = *w1;
	  found = 1;
	  break;
	}
      }
      wb++;
      addr += 4;
    }
    if( found )
      break;
    memcpy( buf, buf + BUFSIZE - PAT_LEN, PAT_LEN );
    offset = PAT_LEN;
  }
  if( found )
  {
    fseek( fl, -( PAT_LEN + l - ( i * 4 ) ), SEEK_CUR );
    fwrite( wb, sizeof( u32 ), 1, fl );
  }
  fclose( fl );
  return 0;
}

int
main( int argc, char *argv[] )
{
  DIR          *dir;
  char         *d_name;
  struct dirent *de;
  struct stat   st;
  char         *dirname = ".";

  if( argc > 1 )
    dirname = strdup( argv[1] );
  if( chdir( dirname ) == -1 )
    return -1;
  dir = opendir( dirname );
  while( ( de = readdir( dir ) ) != NULL )
  {
    d_name = de->d_name;
    if( strncmp( d_name, "lib", 3 ) &&
	strncmp( d_name + strlen( d_name ) - 3, "wll", 3 ) )
      continue;
    if( strstr( d_name, "ida" ) == NULL )
      continue;
#ifdef MINGW
    if( stat( d_name, &st ) != 0 )
      continue;
#else
    if( lstat( d_name, &st ) != 0 )
      continue;
    if( S_ISLNK( st.st_mode ) )
      continue;
#endif
    if( S_ISREG( st.st_mode ) )
      patch_file( d_name );
  }
  return 0;
}
