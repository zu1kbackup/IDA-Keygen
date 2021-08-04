
# How IDA 7.2's installer password was found


*Note: All hashes and passwords are redacted.*

## Previously ...

In January 2019, the installer files for IDA 7.2 were leaked. This does not mean it was usable however, as you need an installer password to install and a licence file to activate it.
Separately to that, a license file from ESET was leaked, which didn't match the feature set of the installer file.

But all the leaks didn't matter, because without the installer password, the program files were safe. Until now. :)

On 2019-06-21, devcore published a [blog post](https://devco.re/blog/2019/06/21/operation-crack-hacking-IDA-Pro-installer-PRNG-from-an-unusual-way-en/) about obvious flaws in the MacOS and Linux installers for IDA, including the password as plaintext in the setup file. The Windows installer, however, uses [InnoSetup](http://www.jrsoftware.org/isinfo.php) as installation engine.

InnoSetup encrypts the program data with the installer password and hashes it via SHA-1, prepending it with `PasswordCheckHash` and eight random bytes as salt. The password being 12 alphanumeric characters long means that bruteforcing it is pretty much out of the question.

Unless you find out how the passwords were generated in the first place! Devcore found out that the passwords are simply generated with a small Perl script using `srand()`/`rand()`. This only works for versions up to 6.8 though, and not even all installers, as *qudiss* noted:

> I noticed [Perl 5.20.0's PRNG implementation](https://rosettacode.org/wiki/Random_number_generator_(included)#Perl) can't be used to find seeds for the other leaked passwords or to bruteforce IDA 7.0-7.2 setup passwords. I assume different algorithms/charsets/etc. were used for these?
>
> — [qudiss](https://devco.re/blog/2019/06/21/operation-crack-hacking-IDA-Pro-installer-PRNG-from-an-unusual-way-en/#comment-4511595557)

I found that interesting and verified their findings by converting the code to Rust and do a full search for all PRNG seeds (assuming a 32-bit seed). To do that I've dug through the Perl source code to find the exact [implementation of DRand48](https://github.com/Perl/perl5/blob/df09255f565b73f060cd59e80498786e0f80d4a7/util.c#L5817). This, converted to Rust, amounts to something like:

```rust
use float_extras::f64::ldexp;

pub struct DRand48 {
    pub x: u64
}

impl DRand48 {
    #[inline]
    pub fn next_f64(&mut self) -> f64 {
        self.x = self.x
            .wrapping_mul(0x5DEE_CE66D)
            .wrapping_add(0xB)
            & 0xFFFF_FFFF_FFFF;
        ldexp(self.x as f64, -48)
    }

    #[inline]
    pub fn set_seed(&mut self, seed: u32) {
        self.x = 0x330Eu64 + (u64::from(seed) << 16);
    }
}
```

The rest is just a big loop over the full 32-bit range, setting the initial seed, generating the password, hashing it according to InnoSetup's scheme, and comparing that with the saved hash in the installer. Using [Rayon](https://github.com/rayon-rs/rayon) I've quickly converted it to use multiple threads, yielding an >8x speed improvement on my system.

... and yes, as qudiss said, neither the IDA 7.0 nor the other mentioned leaked passwords can be found. So, what now?

## Breaking open the 7.0 installer

I guess I was pretty lucky since my first idea was actually correct. Qudiss' comment above included a very helpful link and hint: The PRNG implementation used in Perl was first introduced in Perl 5.20. So I've looked into what Perl used before DRand48 was added, thinking the passwords could have just be generated with an even older version.

And [here](https://github.com/Perl/perl5/blob/05ccd577e15cc66bbb7414fad5ee3c02f536c7a5/uconfig.h#L3096) it is:

```c
#define Drand01()       ((rand() & 0x7FFF) / (double) ((unsigned long)1 << 15))     /**/
#define Rand_seed_t     int    /**/
#define seedDrand01(x)  srand((Rand_seed_t)x)   /**/
```

Just a simple call to the C functions `srand` and `rand`, converting the random number to a double with a bit of bit-fiddling.

Re-checking the full range was a little bit uglier with the older PRNG code, since C's `srand`/`rand` are not thread-safe, as it uses globals to store the PRNG state. This meant that instead of using rayon multithreading, the brute-force loop has to run single-threaded. To make the program not lose all of its previous speed, chunking the search space into 16 blocks and just running the tool 16 times in parallel worked well enough.

```rs
use hex_literal::hex;
use libc::{rand, srand};
use sha1::{Digest, Sha1};
use std::{env, f64};

const CHARS: &[u8; 54] = b"abcdefghijkmpqrstuvwxyzABCDEFGHJKLMPQRSTUVWXYZ23456789";

const HASH: [u8; 20] = hex!("0000000000000000000000000000000000000000");
const PEPPER: &[u8; 17] = b"PasswordCheckHash";
const SALT: [u8; 8] = hex!("0000000000000000");

fn main() {
    let block_str = env::args().nth(1).expect("block");
    let block = block_str.parse::<u32>().expect("block");
    assert!(block < 16);

    let sha1template = {
        let mut hasher = Sha1::new();
        hasher.input(PEPPER);
        hasher.input(SALT);
        hasher
    };

    let start = block << 28;
    let length = 0x0FFF_FFFFu32;

    let mut buf = [0u8; 12];

    for i in start..=(start + length) {
        perl_srand(i);

        for n in &mut buf {
            *n = CHARS[perl_rand(54) as usize];
        }

        let mut hasher = sha1template.clone();
        hasher.input(&buf);

        let hash = hasher.result();

        if hash[..] == HASH {
            println!("FOUND: {}", i);
            return;
        }
    }

    println!("not found");
}

#[inline]
fn perl_srand(seed: u32) {
    unsafe { srand(seed) }
}

#[inline]
fn perl_rand(max: u32) -> u32 {
    (f64::from(unsafe { rand() } & 0x7FFF) / ((1u64 << 15) as f64) * f64::from(max)) as u32
}
```

This, surprisingly, turned out to be the right idea and successfully bruteforced the other hashes/passwords (when using Microsoft's C runtime implementation for `srand` and `rand`).

## IDA 7.2, though

The next thing I've tested was the IDA 7.2 installer, of course. [InnoExtract](http://constexpr.org/innoextract/) (`innoextract.exe --show-password`) is probably the easiest way of extracting the relevant data from the installer:

```plain
Inspecting "IDA Pro v7.2 and Hex-Rays Decompiler (x64)" - setup data version 5.5.7 (unicode)
Password hash: SHA-1 0000000000000000000000000000000000000000
Password salt: 50617373776f7264436865636b486173680000000000000000 (hex bytes, prepended to password)
Password encoding: UTF-16LE
Done.
```

One thing that immediately stood out was the password encoding. IDA 7.2 uses the unicode variant of InnoSetup, hence the UTF16 encoding—previous installers used the ANSI variant. With a bit of unsafe slicing, the DRand48 version of the hashing code looks like this now:

```rs
let mut buf = [0u16; 12];
let mut rand = DRand48 { x: 0 };
for i in pos..(pos + 0xFF_FFFF) {
    rand.set_seed(i);

    let mut n = 0;
    while n < 12 {
        n += (CHARS[(rand.next_f64() * 54.0) as usize] as char)
            .encode_utf16(&mut buf[n..])
            .len();
    }
    let hash = {
        let mut hasher = sha1template.clone();
        hasher.input(unsafe {
            std::slice::from_raw_parts(
                (buf[..]).as_ptr() as *const _,
                buf[..].len() * 2,
            )
        });
        hasher.result()
    };
    if hash[..] == HASH {
        return Some(buf);
    }
}
```

I've tried both the DRand48 PRNG and the older C-based PRNG, to no avail. Giving up for the night I've shared my findings as a reply to qudiss' comment.

On the next morning a lot of comments on both devco.re and the chinese discussion board pediy.com had appeared, pointing to a few more ideas to test. The first one was pretty simple, checking if the password length was increased to 14 characters, which sadly was not the case.

The second hint was posted as a small inconspicuous reply in the comments section on the devco.re blog post, by hishe:

> i think you need to omit the first rand.
>
> this article doesn't mention this.
>
> — [hishe](https://devco.re/blog/2019/06/21/operation-crack-hacking-IDA-Pro-installer-PRNG-from-an-unusual-way-en/#comment-4512664132)

o_O

> Yup, got it!
>
> — [me in reply to hishe](https://devco.re/blog/2019/06/21/operation-crack-hacking-IDA-Pro-installer-PRNG-from-an-unusual-way-en/#comment-4512903087)

It probably was a well-educated guess by hishe that led to IDA 7.2 being finally pried open. Discarding the first generated number after setting the seed was everything that had to be changed to make it work (with DRand48):

```rs
for i in pos..(pos + 0xFF_FFFF) {
    rand.set_seed(i);
    // skip first value
    rand.next_f64();

    // ... (see above)
```

After waiting for somebody else to post the actual password for the installer I pushed my code for anyone interested to see:
[gh/find_drand48_innosetup_pw](https://github.com/seritools/find_drand48_innosetup_pw)

The timing of it all was lucky as well—the weakness was reported to Hex-Rays on January 31st 2019, while the leaks happened just a few weeks earlier. Since Hex-Rays promised to harden the installer password, this will probably be the last version of IDA to be leaked/cracked in a usable state without a password.

