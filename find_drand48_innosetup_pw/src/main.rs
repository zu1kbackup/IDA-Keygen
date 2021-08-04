mod rand48;
use rand48::DRand48;

use hex_literal::hex;
use rayon::iter::*;
use sha1::{Digest, Sha1};

const CHARS: &[u8; 54] = b"abcdefghijkmpqrstuvwxyzABCDEFGHJKLMPQRSTUVWXYZ23456789";

const SALT1: &[u8; 17] = b"PasswordCheckHash";

// change these to the actual values you want to find for
const SALT2: [u8; 8] = hex!("0000000000000000");
const HASH: [u8; 20] = hex!("0000000000000000000000000000000000000000");

fn main() {
    let sha1template = {
        let mut hasher = Sha1::new();
        hasher.input(SALT1);
        hasher.input(SALT2);
        hasher
    };

    let result = (0u32..=0xFF)
        .into_par_iter()
        .filter_map(|n| {
            let pos: u32 = n << 24;
            println!(
                "Checking block {}/256 (seeds {:X}-{:X})",
                n + 1,
                pos,
                (pos + 0xFF_FFFF)
            );

            let mut buf = [0u16; 12];
            let mut rand = DRand48 { x: 0 };
            for i in pos..(pos + 0xFF_FFFF) {
                rand.set_seed(i);

                // skip first value
                rand.next_f64();

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
            None
        })
        .find_any(|_| true);

    if let Some(buf) = result {
        println!("FOUND: {}", String::from_utf16(&buf[..]).unwrap());
    }
}
