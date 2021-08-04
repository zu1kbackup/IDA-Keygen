use float_extras::f64::ldexp;

/// Double Rand48 64bit impl based on perl's PRNG implementation
pub struct DRand48 {
    pub x: u64
}

impl DRand48 {
    #[inline]
    pub fn next_f64(&mut self) -> f64 {
        let x = (self.x.wrapping_mul(0x5DEE_CE66D).wrapping_add(0xB)) & 0xFFFF_FFFF_FFFF;
        self.x = x;
        ldexp(x as f64, -48)
    }

    #[inline]
    pub fn set_seed(&mut self, seed: u32) {
        const FREEBSD_DRAND48_SEED_0: u64 = 0x330e;
        self.x = FREEBSD_DRAND48_SEED_0 + (u64::from(seed) << 16);
    }
}