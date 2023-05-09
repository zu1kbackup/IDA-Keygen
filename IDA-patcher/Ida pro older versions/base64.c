#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>

#ifndef _MY_Uxx
#define _MY_Uxx
typedef uint8_t u8;
typedef uint16_t u16;
typedef uint32_t u32;
typedef uint64_t u64;
#endif

static const char *bintoasc =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
static const u8 asctobin[] = {
  0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80,
  0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80,
  0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80,
  0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80,
  0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80,
  0x80, 0x80, 0x80, 0x3e, 0x80, 0x80, 0x80, 0x3f,
  0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3a, 0x3b,
  0x3c, 0x3d, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80,
  0x80, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06,
  0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
  0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16,
  0x17, 0x18, 0x19, 0x80, 0x80, 0x80, 0x80, 0x80,
  0x80, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20,
  0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28,
  0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f, 0x30,
  0x31, 0x32, 0x33, 0x80, 0x80, 0x80, 0x80, 0x80
};

/* ENC is the basic 1 character encoding function to make a char printing */
#define ENC(c) ((int)bintoasc[((c) & 077)])
#define PAD		'='

/* output one group of up to 3 bytes, pointed at by p */
int
line_base64( char *d, u8 * p, int l )
{
  u8          c1, c2, c3, c4;
  u8          p0, p1, p2;
  int	      chnr = 0;

  while ( l > 0 )
  {
    p0 = *p++;
    if ( l > 1 )
      p1 = *p++;
    else
      p1 = 0;
    if ( l > 2 )
      p2 = *p++;
    else
      p2 = 0;
    c1 = p0 >> 2;
    c2 = ( ( p0 << 4 ) & 060 ) | ( ( p1 >> 4 ) & 017 );
    c3 = ( ( p1 << 2 ) & 074 ) | ( ( p2 >> 6 ) & 03 );
    c4 = p2 & 077;
    *d++ = ENC( c1 );
    *d++ = ENC( c2 );
    if ( l == 1 )
    {
      *d++ = PAD;
      *d++ = PAD;
    }
    else
    {
      *d++ = ENC( c3 );
      if ( l == 2 )
	*d++ = PAD;
      else
	*d++ = ENC( c4 );
    }
    l -= 3;
    chnr += 4;
  }
  *d = '\0';
  return chnr;
}

u8         *
base64tobin( u8 * inbuf, unsigned inlen, unsigned *outlen )
{
  u8         *outbuf;
  u8         *outp;		// malloc'd outbuf size
  unsigned      obuflen;
  u8         *bp;
  unsigned      olen = 0;	// actual output size
  u8          c1, c2, c3, c4;
  u8          j;
  unsigned      clen;

  // Strip out all whitespace; remainder must be multiple of four characters
  if ( ( inlen & 0x03 ) != 0 )
    return NULL;
  bp = inbuf;
  obuflen = ( inlen / 4 ) * 3;
  outbuf = ( u8 * ) malloc( obuflen );
  outp = outbuf;

  while ( inlen )
  {
    // Note inlen is always a multiple of four here
    if ( *bp & 0x80 || ( c1 = asctobin[*bp] ) & 0x80 )
      goto errorOut;
    inlen--;
    bp++;
    if ( *bp & 0x80 || ( c2 = asctobin[*bp] ) & 0x80 )
      goto errorOut;
    inlen--;
    bp++;
    if ( *bp == PAD )
    {
      // two input bytes, one output byte
      c3 = c4 = 0;
      clen = 1;
      if ( c2 & 0xf )
	goto errorOut;
      bp++;
      inlen--;
      if ( *bp == PAD )
      {
	bp++;
	inlen--;
	if ( inlen > 0 )
	  goto errorOut;
      }
      else
	goto errorOut;
    }
    else if ( *bp & 0x80 || ( c3 = asctobin[*bp] ) & 0x80 )
      goto errorOut;
    else
    {
      bp++;
      inlen--;
      if ( *bp == PAD )
      {
	// Three input bytes, two output
	c4 = 0;
	clen = 2;
	if ( c3 & 3 )
	  goto errorOut;
      }
      else if ( *bp & 0x80 || ( c4 = asctobin[*bp] ) & 0x80 )
	goto errorOut;
      else
	clen = 3; // Normal non-pad case
      bp++;
      inlen--;
    }
    j = ( c1 << 2 ) | ( c2 >> 4 );
    *outp++ = j;
    if ( clen > 1 )
    {
      j = ( c2 << 4 ) | ( c3 >> 2 );
      *outp++ = j;
      if ( clen == 3 )
      {
	j = ( c3 << 6 ) | c4;
	*outp++ = j;
      }
    }
    olen += clen;
  }
  *outlen = olen;
  return outbuf;
errorOut:
  free( outbuf );
  return NULL;
}
