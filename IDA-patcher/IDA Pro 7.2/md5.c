#include <stdlib.h>
#include <string.h>
#include "md5.h"

/***************************************************************************
*  Implementation RSA Data Security, Inc. MD5 Message-Digest Algorithm	   *
****************************************************************************/

/* To form the message digest for a message M, initialize a context buffer
   mdContext using MD5Init(); call MD5Update() on mdContext and M; and call
   MD5Final() on mdContext.  The message digest is now in
   mdContext->digest[ 0 ... 15 ] */

/****************************************************************************
*									    *
*   The MD5 Transformation						    *
*									    *
****************************************************************************/

/* The Constants used in the MD5 transformation */

static u32    mConst[MD5_ROUNDS] = { 3614090360U, 3905402710U, 606105819U,
  3250441966U, 4118548399U, 1200080426U, 2821735955U, 4249261313U,
  1770035416U, 2336552879U, 4294925233U, 2304563134U, 1804603682U,
  4254626195U, 2792965006U, 1236535329U, 4129170786U, 3225465664U,
  643717713U, 3921069994U, 3593408605U, 38016083U, 3634488961U,
  3889429448U, 568446438U, 3275163606U, 4107603335U, 1163531501U,
  2850285829U, 4243563512U, 1735328473U, 2368359562U, 4294588738U,
  2272392833U, 1839030562U, 4259657740U, 2763975236U, 1272893353U,
  4139469664U, 3200236656U, 681279174U, 3936430074U, 3572445317U,
  76029189U, 3654602809U, 3873151461U, 530742520U, 3299628645U,
  4096336452U, 1126891415U, 2878612391U, 4237533241U, 1700485571U,
  2399980690U, 4293915773U, 2240044497U, 1873313359U, 4264355552U,
  2734768916U, 1309151649U, 4149444226U, 3174756917U, 718787259U,
  3951481745U
};

/* F, G, H and I are basic MD5 functions */

#define F(X,Y,Z)  ( ( X & Y ) | ( ~X & Z ) )
#define G(X,Y,Z)  ( ( X & Z ) | ( Y & ~Z ) )
#define H(X,Y,Z)  ( X ^ Y ^ Z )
#define I(X,Y,Z)  ( Y ^ ( X | ~Z ) )

/* ROTATE_LEFT rotates x left n bits */

#define ROTATE_LEFT(x,n)  ( ( x << n ) | ( x >> ( 32 - n ) ) )

/* FF, GG, HH, and II transformations for rounds 1, 2, 3, and 4.  Rotation is
   separate from addition to prevent recomputation */

#define FF(A,B,C,D,X,shiftAmt,magicConst) \
  { \
  A += F( B, C, D ) + X + magicConst; \
  A = ROTATE_LEFT( A, shiftAmt ); \
  A += B; \
  }

#define GG(A,B,C,D,X,shiftAmt,magicConst) \
  { \
  A += G( B, C, D ) + X + magicConst; \
  A = ROTATE_LEFT( A, shiftAmt ); \
  A += B; \
  }

#define HH(A,B,C,D,X,shiftAmt,magicConst) \
  { \
  A += H( B, C, D ) + X + magicConst; \
  A = ROTATE_LEFT( A, shiftAmt ); \
  A += B; \
  }

#define II(A,B,C,D,X,shiftAmt,magicConst) \
  { \
  A += I( B, C, D ) + X + magicConst; \
  A = ROTATE_LEFT( A, shiftAmt ); \
  A += B; \
  }

/* Round 1 shift amounts */

#define S11  7
#define S12  12
#define S13  17
#define S14  22

/* Round 2 shift amounts */

#define S21 5
#define S22 9
#define S23 14
#define S24 20

/* Round 3 shift amounts */

#define S31 4
#define S32 11
#define S33 16
#define S34 23

/* Round 4 shift amounts */

#define S41 6
#define S42 10
#define S43 15
#define S44 21

/* Basic MD5 step. Transforms buf based on in.  */

void
MD5Transform( u32 * buf, u32 * in )
{
  u32           A = buf[0], B = buf[1], C = buf[2], D = buf[3];

  /*
   * Round 1 
   */
  FF( A, B, C, D, in[0], S11, mConst[0] );	/* 1 */
  FF( D, A, B, C, in[1], S12, mConst[1] );	/* 2 */
  FF( C, D, A, B, in[2], S13, mConst[2] );	/* 3 */
  FF( B, C, D, A, in[3], S14, mConst[3] );	/* 4 */
  FF( A, B, C, D, in[4], S11, mConst[4] );	/* 5 */
  FF( D, A, B, C, in[5], S12, mConst[5] );	/* 6 */
  FF( C, D, A, B, in[6], S13, mConst[6] );	/* 7 */
  FF( B, C, D, A, in[7], S14, mConst[7] );	/* 8 */
  FF( A, B, C, D, in[8], S11, mConst[8] );	/* 9 */
  FF( D, A, B, C, in[9], S12, mConst[9] );	/* 10 */
  FF( C, D, A, B, in[10], S13, mConst[10] );	/* 11 */
  FF( B, C, D, A, in[11], S14, mConst[11] );	/* 12 */
  FF( A, B, C, D, in[12], S11, mConst[12] );	/* 13 */
  FF( D, A, B, C, in[13], S12, mConst[13] );	/* 14 */
  FF( C, D, A, B, in[14], S13, mConst[14] );	/* 15 */
  FF( B, C, D, A, in[15], S14, mConst[15] );	/* 16 */

  /*
   * Round 2 
   */
  GG( A, B, C, D, in[1], S21, mConst[16] );	/* 17 */
  GG( D, A, B, C, in[6], S22, mConst[17] );	/* 18 */
  GG( C, D, A, B, in[11], S23, mConst[18] );	/* 19 */
  GG( B, C, D, A, in[0], S24, mConst[19] );	/* 20 */
  GG( A, B, C, D, in[5], S21, mConst[20] );	/* 21 */
  GG( D, A, B, C, in[10], S22, mConst[21] );	/* 22 */
  GG( C, D, A, B, in[15], S23, mConst[22] );	/* 23 */
  GG( B, C, D, A, in[4], S24, mConst[23] );	/* 24 */
  GG( A, B, C, D, in[9], S21, mConst[24] );	/* 25 */
  GG( D, A, B, C, in[14], S22, mConst[25] );	/* 26 */
  GG( C, D, A, B, in[3], S23, mConst[26] );	/* 27 */
  GG( B, C, D, A, in[8], S24, mConst[27] );	/* 28 */
  GG( A, B, C, D, in[13], S21, mConst[28] );	/* 29 */
  GG( D, A, B, C, in[2], S22, mConst[29] );	/* 30 */
  GG( C, D, A, B, in[7], S23, mConst[30] );	/* 31 */
  GG( B, C, D, A, in[12], S24, mConst[31] );	/* 32 */

  /*
   * Round 3 
   */
  HH( A, B, C, D, in[5], S31, mConst[32] );	/* 33 */
  HH( D, A, B, C, in[8], S32, mConst[33] );	/* 34 */
  HH( C, D, A, B, in[11], S33, mConst[34] );	/* 35 */
  HH( B, C, D, A, in[14], S34, mConst[35] );	/* 36 */
  HH( A, B, C, D, in[1], S31, mConst[36] );	/* 37 */
  HH( D, A, B, C, in[4], S32, mConst[37] );	/* 38 */
  HH( C, D, A, B, in[7], S33, mConst[38] );	/* 39 */
  HH( B, C, D, A, in[10], S34, mConst[39] );	/* 40 */
  HH( A, B, C, D, in[13], S31, mConst[40] );	/* 41 */
  HH( D, A, B, C, in[0], S32, mConst[41] );	/* 42 */
  HH( C, D, A, B, in[3], S33, mConst[42] );	/* 43 */
  HH( B, C, D, A, in[6], S34, mConst[43] );	/* 44 */
  HH( A, B, C, D, in[9], S31, mConst[44] );	/* 45 */
  HH( D, A, B, C, in[12], S32, mConst[45] );	/* 46 */
  HH( C, D, A, B, in[15], S33, mConst[46] );	/* 47 */
  HH( B, C, D, A, in[2], S34, mConst[47] );	/* 48 */

  /*
   * Round 4 
   */
  II( A, B, C, D, in[0], S41, mConst[48] );	/* 49 */
  II( D, A, B, C, in[7], S42, mConst[49] );	/* 50 */
  II( C, D, A, B, in[14], S43, mConst[50] );	/* 51 */
  II( B, C, D, A, in[5], S44, mConst[51] );	/* 52 */
  II( A, B, C, D, in[12], S41, mConst[52] );	/* 53 */
  II( D, A, B, C, in[3], S42, mConst[53] );	/* 54 */
  II( C, D, A, B, in[10], S43, mConst[54] );	/* 55 */
  II( B, C, D, A, in[1], S44, mConst[55] );	/* 56 */
  II( A, B, C, D, in[8], S41, mConst[56] );	/* 57 */
  II( D, A, B, C, in[15], S42, mConst[57] );	/* 58 */
  II( C, D, A, B, in[6], S43, mConst[58] );	/* 59 */
  II( B, C, D, A, in[13], S44, mConst[59] );	/* 60 */
  II( A, B, C, D, in[4], S41, mConst[60] );	/* 61 */
  II( D, A, B, C, in[11], S42, mConst[61] );	/* 62 */
  II( C, D, A, B, in[2], S43, mConst[62] );	/* 63 */
  II( B, C, D, A, in[9], S44, mConst[63] );	/* 64 */

  buf[0] += A;
  buf[1] += B;
  buf[2] += C;
  buf[3] += D;
}

/************************************************************************
*   MD5 Support Routines						*
*************************************************************************/

/* The routine MD5Init initializes the message-digest context mdContext. All
   fields are set to zero */

void
MD5Init( MD5_CTX * mdContext )
{
  mdContext->i[0] = mdContext->i[1] = 0L;

  /*
   * Load magic initialization constants 
   */
  mdContext->buf[0] = 0x67452301L;
  mdContext->buf[1] = 0xEFCDAB89L;
  mdContext->buf[2] = 0x98BADCFEL;
  mdContext->buf[3] = 0x10325476L;

/* The routine MD5Update updates the message-digest context to account for
   the presence of each of the characters inBuf[ 0 .. inLen-1 ] in the
   message whose digest is being computed.  This is an optimized version
   which assumes that the buffer is a multiple of MD5_BLOCKSIZE bytes long */
}

void
MD5Update( MD5_CTX * mdContext, u8 * inBuf, unsigned int inLen )
{
  int           mdi;
  u32           in[16];
  unsigned int  i, ii;

  /*
   * Compute number of bytes mod 64 
   */
  mdi = ( int ) ( ( mdContext->i[0] >> 3 ) & 0x3F );

  /*
   * Update number of bits 
   */
  if ( ( mdContext->i[0] + ( ( u32 ) inLen << 3 ) ) < mdContext->i[0] )
    mdContext->i[1]++;		/* Carry from low to high bitCount */
  mdContext->i[0] += ( ( u32 ) inLen << 3 );
  mdContext->i[1] += ( ( u32 ) inLen >> 29 );

  while ( inLen-- )
  {
    /*
     * Add new character to buffer, increment mdi 
     */
    mdContext->in[mdi++] = *inBuf++;

    /*
     * Transform if necessary 
     */
    if ( mdi == 0x40 )
    {
      for ( i = 0, ii = 0; i < 16; i++, ii += 4 )
	in[i] = ( ( ( u32 ) mdContext->in[ii + 3] ) << 24 ) |
	    ( ( ( u32 ) mdContext->in[ii + 2] ) << 16 ) |
	    ( ( ( u32 ) mdContext->in[ii + 1] ) << 8 ) |
	    ( ( u32 ) mdContext->in[ii] );
      MD5Transform( mdContext->buf, in );
      mdi = 0;
    }
  }
}

/* The routine MD5Final terminates the message-digest computation and ends
   with the desired message digest in mdContext->digest[ 0 ... 15 ] */

void
MD5Final( MD5_CTX * mdContext )
{
  int           mdi, padLen;
  u8            padding[64];
  unsigned int  i, ii;
  u32           in[16];

  /*
   * Save number of bits 
   */
  in[14] = mdContext->i[0];
  in[15] = mdContext->i[1];

  /*
   * Compute number of bytes mod 64 
   */
  mdi = ( int ) ( ( mdContext->i[0] >> 3 ) & 0x3F );

  /*
   * Pad out to 56 mod 64 
   */
  padLen = ( mdi < 56 ) ? ( 56 - mdi ) : ( 120 - mdi );
  padding[0] = 0x80;
  memset( padding + 1, 0, padLen - 1 );
  MD5Update( mdContext, padding, padLen );

  /*
   * Append length in bits and transform 
   */
  for ( i = 0, ii = 0; i < 14; i++, ii += 4 )
    in[i] = ( ( ( u32 ) mdContext->in[ii + 3] ) << 24 ) |
	( ( ( u32 ) mdContext->in[ii + 2] ) << 16 ) |
	( ( ( u32 ) mdContext->in[ii + 1] ) << 8 ) |
	( ( u32 ) mdContext->in[ii] );
  MD5Transform( mdContext->buf, in );

  /*
   * Store buffer in digest 
   */
  for ( i = 0, ii = 0; i < 4; i++, ii += 4 )
  {
    mdContext->digest[ii] = ( u8 ) ( mdContext->buf[i] & 0xFF );
    mdContext->digest[ii + 1] = ( u8 ) ( ( mdContext->buf[i] >> 8 ) & 0xFF );
    mdContext->digest[ii + 2] = ( u8 ) ( ( mdContext->buf[i] >> 16 ) & 0xFF );
    mdContext->digest[ii + 3] = ( u8 ) ( ( mdContext->buf[i] >> 24 ) & 0xFF );
  }
}
