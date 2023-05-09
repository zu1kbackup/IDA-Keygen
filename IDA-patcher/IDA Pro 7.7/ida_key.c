#define _XOPEN_SOURCE
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <getopt.h>
#include <time.h>
#include "bigint.h"
#include "md5.h"

struct license
{
  u8		zero;
  u16		mark;
  u16		ver;
  u16		type;		// + 4
  u16		seats;		// + 6
  u32		cap1;		// + 8
  u32		cap2;		// + c
  u32		t_issue;	// + 10
  u32		t_trial_end;	// + 14
  u32		t_support_end;	// + 18
  u8		id[6];		// + 1c
  char		name[77];	// + 22
  u8		md5[16];
} __attribute__ ( ( __packed__ ) );

u8	      sign_read[160];
u8	      new_lic[128];
u8	      rnd_bytes[128];

struct
{
  int		sign_key:1;
  int		force_key:1;
  int		new_type:1;
} sw;

// original RSA modulus (reversed)
u8	      mod_rsa[] = {
  0xed, 0xfd, 0x42, 0x5c, 0xf9, 0x78, 0x54, 0x6e, 0x89, 0x11, 0x22, 0x58, 0x84,
  0x43, 0x6c, 0x57, 0x14, 5, 0x25, 0x65, 0xb, 0xcf, 0x6e, 0xbf, 0xe8, 0xe,
  0xdb, 0xc5, 0xfb, 0x1d, 0xe6, 0x8f, 0x4c, 0x66, 0xc2, 0x9c, 0xb2, 0x2e, 0xb6,
  0x68, 0x78, 0x8a, 0xfc, 0xb0, 0xab, 0xbb, 0x71, 0x80, 0x44, 0x58, 0x4b, 0x81,
  0xf, 0x89, 0x70, 0xcd, 0xdf, 0x22, 0x73, 0x85, 0xf7, 0x5d, 0x5d, 0xdd, 0xd9,
  0x1d, 0x4f, 0x18, 0x93, 0x7a, 8, 0xaa, 0x83, 0xb2, 0x8c, 0x49, 0xd1, 0x2d,
  0xc9, 0x2e, 0x75, 5, 0xbb, 0x38, 0x80, 0x9e, 0x91, 0xbd, 0xf, 0xbd, 0x2f,
  0x2e, 0x6a, 0xb1, 0xd2, 0xe3, 0x3c, 0xc, 0x55, 0xd5, 0xbd, 0xdd, 0x47, 0x8e,
  0xe8, 0xbf, 0x84, 0x5f, 0xce, 0xf3, 0xc8, 0x2b, 0x9d, 0x29, 0x29, 0xec, 0xb7,
  0x1f, 0x4d, 0x1b, 0x3d, 0xb9, 0x6e, 0x3a, 0x8e, 0x7a, 0xaf, 0x93
};

// private key for the patched RSA modulus
u8	      pri_key[] = {
  0x74, 0x98, 2, 0x70, 0x49, 0x14, 0xb, 0x81, 0x15, 0x8d, 0xba, 0xb9, 0x9f,
  0x7e, 0xd0, 2, 0xd1, 0xb9, 0x98, 0xe, 0xb7, 0x32, 0xe8, 0x59, 0x47, 0xe7,
  0xe4, 0xf4, 0x2f, 0x28, 0x32, 0x15, 0x1f, 0xa6, 0x56, 0x2b, 0x67, 0xd4, 0xd8,
  0xa0, 0xa3, 0x22, 0x1e, 0xd1, 4, 0x5d, 0xc0, 0xf0, 0xb9, 0x25, 0x8f, 0xf6,
  0x11, 0xa4, 0xf8, 0xb8, 0xc9, 0x9a, 0xe7, 0x81, 0x99, 0xed, 0x9e, 0x4d, 0xae,
  0xc2, 0xf9, 0x57, 0x9f, 0x3f, 0xf3, 0x1c, 0x79, 0xc4, 0xa2, 0x19, 0xb6, 0xea,
  0xa4, 0, 0x2f, 0x82, 0x35, 0xd8, 0x63, 0x4e, 0x1c, 0x7a, 1, 0xd3, 0x32, 0x57,
  0x1d, 0x71, 0xd, 0x64, 0xdd, 0x64, 0xd4, 0x4d, 0x81, 0x41, 0x26, 0xb7, 0xbf,
  0x8d, 0x60, 0x16, 0x78, 0x45, 0xa5, 0xb1, 0xbe, 0x47, 0xff, 0x68, 0x7b, 0x79,
  0x36, 0x44, 0x13, 0xbb, 0xf3, 0xb7, 0xbb, 0x6a, 0xc8, 0x77
};

u8	      pub_rsa = 0x13;

int	      line_base64( char *d, u8 * p, int l );
u8	     *base64tobin( u8 * inbuf, unsigned inlen, unsigned *outlen );

void
dump_sign_h( u8 * s )
{
  FILE	       *f;
  int		i, l, tl;

  if( ( f = fopen( "anon_idb.h", "w" ) ) != NULL )
  {
    fprintf( f, "%s\n", "u8\thexData[] = {" );
    tl = 128;
    while( tl )
    {
      l = tl > 16 ? 16 : tl;
      fputc( '"', f );
      for( i = 0; i < l; i++ )
	fprintf( f, "\\x%02x", *s++ );
      fputc( '"', f );
      fputc( '\n', f );
      tl -= l;
    }
    fputc( '}', f );
    fputc( ';', f );
    fclose( f );
  }
}

void
reverse_key( u8 * buf )
{
  int		i;
  u8		t;

  for( i = 0; i < 64; i++ )
  {
    t = buf[i];
    buf[i] = buf[127 - i];
    buf[127 - i] = t;
  }
}

void
display_license( struct license *lic )
{
  int		l;
  char	       *lic_type = "none";

  for( l = 0; l < 80; l++ )
    putchar( '-' );
  putchar( '\n' );
  printf( "Version: %d\n", lic->ver );
  printf( "Mark: 0x%x\n", lic->mark );
  printf( "Cap1: 0x%x\n", lic->cap1 );
  printf( "Cap2: 0x%x\n", lic->cap2 );
  if( lic->t_issue )
    printf( "Issue time: %s", ctime( ( const time_t * ) &lic->t_issue ) );
  if( lic->t_trial_end )
    printf( "Expiry time: %s",
	ctime( ( const time_t * ) &lic->t_trial_end ) );
  if( lic->t_support_end )
    printf( "Support End time: %s",
	ctime( ( const time_t * ) &lic->t_support_end ) );
  if( lic->type == 1 )
    lic_type = "named";
  else if( lic->type == 2 )
    lic_type = "computer";
  else if( lic->type == 3 )
    lic_type = "floating";
  printf( "Type: %d (%s)\n", lic->type, lic_type );
  printf( "Seats: %d\n", lic->seats );
  printf( "Name: %s\n", lic->name );
  printf( "LicID: " );
  for( l = 0; l < 6; l++ )
    printf( "%02x", lic->id[l] );
  printf( "\n" );
  if( sw.new_type )
  {
    printf( "MD5sum: " );
    for( l = 0; l < 16; l++ )
      printf( "%02x", lic->md5[l] );
    printf( "\n" );
  }
  for( l = 0; l < 80; l++ )
    putchar( '-' );
  putchar( '\n' );
}

u8	     *
license_defaults( struct license *lic )
{
  u8	       *rnd_p;
  u16	       *rnd_w;
  int		i;

  srand( time( NULL ) );
  rnd_w = ( u16 * ) rnd_bytes;
  for( i = 0; i < 128 / sizeof( u16 ); i++ )
    *rnd_w++ = ( u16 ) rand(  );
  rnd_p = rnd_bytes + 5;	// waste a few random bytes
  lic->mark = *( ( u16 * ) ( rnd_p )++ ) & 0x7fff;
  lic->ver = 700;
  lic->type = 2;		// 1 named, 2 computer, 3 floating
  lic->seats = 12;
  lic->t_trial_end = 0;
  lic->t_support_end = 0;
  lic->cap1 = -1;		// 'pro' if both at -1, else 'starter'
  lic->cap2 = -1;
  lic->id[0] = 0x48;
  lic->id[1] = *rnd_p++;
  lic->id[2] = *rnd_p++;
  lic->id[3] = *rnd_p++;
  lic->id[4] = *rnd_p++;
  lic->id[5] = *rnd_p++;
  lic->t_issue = time( NULL );
  return rnd_p;
}

void
usage( char *progname )
{
  fprintf( stderr, "\n%s [-sf] (key_file)\n", progname );
  fprintf( stderr, "\t-s\tsign IDA key with new RSA key\n" );
  fprintf( stderr,
      "\t-f\tforce the use of the new RSA key while decoding\n" );
  exit( 0 );
}

int
main( int argc, char *argv[] )
{
  FILE	       *f;
  MD5_CTX	ctx;
  BI_CTX       *BI;
  bigint       *pri, *pub, *mod, *msg, *emsg;
  int		i, l, dec_l;
  int		id0, id1, id2, id3, id4, id5, lic_id = 0;
  int		option;
  u8	       *s, *d, *rnd_p = NULL;
  char	       *fname, *v, c, line[160];
  struct tm	tm;
  struct license *lic;

  reverse_key( mod_rsa );
  BI = bi_initialize(  );

  do
  {
    option = getopt( argc, argv, "hsf" );
    switch ( option )
    {
      case 's':
	sw.sign_key = 1;
	break;
      case 'f':
	sw.force_key = 1;
	break;
      case 'h':
	usage( argv[0] );
	break;
      case EOF:		// no more options
	break;
      default:
	fprintf( stderr, "getopt returned impossible value: %d ('%c')",
	    option, option );
    }
  }
  while( option != EOF );

  if( optind == argc )
    fname = "ida.key";
  else
    fname = argv[optind++];

  if( ( f = fopen( fname, "rb" ) ) == NULL )
  {
    usage( argv[0] );
    return -1;
  }
  lic = ( struct license * ) new_lic;
  if( sw.sign_key )
    rnd_p = license_defaults( lic );
  d = sign_read;
  MD5Init( &ctx );
  while( fgets( line, 160, f ) != NULL )
  {
    float	  fver;

    l = strlen( line );
    while( l && ( line[l - 1] == '\r' || line[l - 1] == '\n' ) )
    {
      l--;
      line[l] = 0;
    }
    v = strchr( line, 'v' );
    if( v && v > line && *(v-1) != ' ' )
      v = NULL;
    if( sscanf( line, "HEXRAYS_LICENSE %f", &fver ) == 1 ||
        ( v && sscanf( v, "v%f>", &fver) == 1 ) )
    {
      lic->ver = ( u16 ) ( fver * 100. + .5 );
    }
    if( sscanf( line, "%02X-%02X%02X-%02X%02X-%02X",
	&id0, &id1, &id2, &id3, &id4, &id5 ) == 6 )
    {
      if( sw.sign_key )
      {
	s = line + 3;
	for( i = 0; i < 5; i++ )
	{
	  c = '0' + ( ( *rnd_p >> 4 ) & 0xf );
	  if( c > '9' )
	    c += 7;
	  *s++ = c;
	  c = '0' + ( *rnd_p & 0xf );
	  if( c > '9' )
	    c += 7;
	  *s++ = c;
	  rnd_p++;
	  if( i == 1 || i == 3 )
	    s++;
	}
      }
      if( !lic_id && sscanf( line, "%02X-%02X%02X-%02X%02X-%02X",
	  &id0, &id1, &id2, &id3, &id4, &id5 ) == 6 )
      {
	lic->id[0] = id0;
	lic->id[1] = id1;
	lic->id[2] = id2;
	lic->id[3] = id3;
	lic->id[4] = id4;
	lic->id[5] = id5;
	lic_id = 1;
      }
    }
    if( !strncmp( line, "USER", sizeof( "USER" ) - 1 ) )
    {
      s = line + sizeof( "USER" ) - 1;
      while( *s == ' ' || *s == '\t' )
	s++;
      strcpy( lic->name, s );
    }
    if( ( s = strchr( line, '@' ) ) != NULL )
    {
      if( strchr( s, '>' ) != NULL )	// old style license
	strcpy( lic->name, line );
    }
    if( !strncmp( line, "ISSUED_ON", sizeof( "ISSUED_ON" ) - 1 ) )
    {
      s = line + sizeof( "ISSUED_ON" ) - 1;
      while( *s == ' ' || *s == '\t' )
	s++;
      if( sscanf( s, "%d-%d-%d %d:%d:%d",
	  &tm.tm_year, &tm.tm_mon, &tm.tm_mday,
	  &tm.tm_hour, &tm.tm_min, &tm.tm_sec ) == 6 )
      {
	tm.tm_year -= 1900;
	tm.tm_mon--;
	lic->t_issue = mktime( &tm );
      }
    }
    if( sw.sign_key && l > 1 && line[0] == 'R' && line[1] == ':' )
    {
      line_base64( line + 2, rnd_bytes, 57 );
      l = strlen( line );
    }
    if( l > 1 && line[0] == 'S' && line[1] == ':' )
    {
      s = base64tobin( line + 2, l - 2, &dec_l );
      if( dec_l && dec_l <= 128 )
      {
	memcpy( d, s, dec_l );
	d += dec_l;
	sw.new_type = 1;
      }
    }
    else
    {
      // ignore lines with too many binary characters
      if( l )
      {
	int	      binchar = 0;

	for( i = 0; i < l; i++ )
	  if( line[i] != '\t' && ( line[i] < ' ' || line[i] > '}' ) )
	    binchar++;
	if( binchar >= l / 4 )
	  continue;
      }
      printf( "%s\n", line );
      if( l )
	MD5Update( &ctx, line, l );
    }
  }				// end while
  MD5Final( &ctx );
  memcpy( lic->md5, ctx.digest, 16 );
  if( !sw.new_type )
  {
    fseek( f, -160, SEEK_END );
    fread( sign_read, 1, 128, f );
  }
  fclose( f );
  reverse_key( sign_read );
  if( !sw.sign_key && sw.new_type )
  {
    s = ctx.digest;
    printf( "MD5sum: " );
    for( l = 0; l < 16; l++ )
      printf( "%02x", *s++ );
    printf( "\n" );
  }
  if( sw.sign_key || sw.force_key )
    mod_rsa[127 - 3] = 0xcb;
  mod = bi_import( BI, mod_rsa, 128 );
  bi_set_mod( BI, mod, BIGINT_M_OFFSET );
  if( sw.sign_key )
  {
    // adjust the support end to max 10 years ahead of the issue time
    lic->t_support_end = lic->t_issue +
	( *( ( u32 * ) ( rnd_p )++ ) & ( ( 1 << 29 ) - 1 ) );
    if( !sw.new_type )		// old type needs a pre-signature
    {
      lic->cap1 = 0;
      lic->cap2 = 0;
    }
    pri = bi_import( BI, pri_key, 128 );
    msg = bi_import( BI, new_lic, 128 );
    emsg = bi_mod_power( BI, msg, pri );
    bi_export( BI, emsg, sign_read, 128 );
    reverse_key( sign_read );
    dump_sign_h( sign_read );
    s = sign_read;
    dec_l = 160;
    if( sw.new_type )
    {
      while( dec_l )
      {
	l = dec_l > 57 ? 57 : dec_l;
	line_base64( line, s, l );
	printf( "S:%s\n", line );
	s += l;
	dec_l -= l;
      }
    }
    else			// old type license
    {
      fwrite( s, 1, dec_l, stdout );
      lic->cap1 = -1;
      lic->cap2 = -1;
      pri = bi_import( BI, pri_key, 128 );
      msg = bi_import( BI, new_lic, 128 );
      emsg = bi_mod_power( BI, msg, pri );
      bi_export( BI, emsg, sign_read, 128 );
      reverse_key( sign_read );
      fwrite( s, 1, dec_l, stdout );
    }
  }
  else
  {
    msg = bi_import( BI, sign_read, 128 );
    pub = int_to_bi( BI, pub_rsa );
    emsg = bi_mod_power( BI, msg, pub );
    bi_export( BI, emsg, new_lic, 128 );
    display_license( lic );
  }
  bi_free_mod( BI, BIGINT_M_OFFSET );
  bi_terminate( BI );
  return 0;
}
