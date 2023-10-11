//! Implementation of the Heys' Cipher
use std::error::Error;

type Result<T> = core::result::Result<T, Box<dyn Error>>;

const SBOX: [(u16, u16); 16] = [
    (0x0, 0xE),
    (0x1, 0x4),
    (0x2, 0xD),
    (0x3, 0x1),
    (0x4, 0x2),
    (0x5, 0xF),
    (0x6, 0xB),
    (0x7, 0x8),
    (0x8, 0x3),
    (0x9, 0xA),
    (0xA, 0x6),
    (0xB, 0xC),
    (0xC, 0x5),
    (0xD, 0x9),
    (0xE, 0x0),
    (0xF, 0x7),
];

const SBOX_INVERT: [(u16, u16); 16] = [
    (0xE, 0x0),
    (0x4, 0x1),
    (0xD, 0x2),
    (0x1, 0x3),
    (0x2, 0x4),
    (0xF, 0x5),
    (0xB, 0x6),
    (0x8, 0x7),
    (0x3, 0x8),
    (0xA, 0x9),
    (0x6, 0xA),
    (0xC, 0xB),
    (0x5, 0xC),
    (0x9, 0xD),
    (0x0, 0xE),
    (0x7, 0xF),
];

const PERMUTATION: [(u16, u16); 16] = [
    (0x8000, 0x8000),
    (0x4000, 0x0800),
    (0x2000, 0x0080),
    (0x1000, 0x0008),
    (0x0800, 0x4000),
    (0x0400, 0x0400),
    (0x0200, 0x0040),
    (0x0100, 0x0004),
    (0x0080, 0x2000),
    (0x0040, 0x0200),
    (0x0020, 0x0020),
    (0x0010, 0x0002),
    (0x0008, 0x1000),
    (0x0004, 0x0100),
    (0x0002, 0x0010),
    (0x0001, 0x0001),
];

const PERMUTATION_INVERT: [(u16, u16); 16] = [
    (0x8000, 0x8000),
    (0x0800, 0x4000),
    (0x0080, 0x2000),
    (0x0008, 0x1000),
    (0x4000, 0x0800),
    (0x0400, 0x0400),
    (0x0040, 0x0200),
    (0x0004, 0x0100),
    (0x2000, 0x0080),
    (0x0200, 0x0040),
    (0x0020, 0x0020),
    (0x0002, 0x0010),
    (0x1000, 0x0008),
    (0x0100, 0x0004),
    (0x0010, 0x0002),
    (0x0001, 0x0001),
];

fn lookup(kvpairs: &[(u16, u16)], val: u16) -> Result<u16> {
    for (from, to) in kvpairs {
        if *from == val {
            return Ok(*to);
        }
    }
    return Err("Lookup failed".into());
}

/// A 16-bit block, could be a plaintext, ciphertext, or some intermediary
/// state
#[derive(Debug, Eq, PartialEq)]
pub struct Block {
    val: u16,
}

impl Block {
    pub fn new(val: u16) -> Self {
        return Self { val };
    }

    /// Get block from some 16-character binary string
    pub fn from_binstr(binstr: &str) -> Result<Self> {
        let val = u16::from_str_radix(binstr, 2)?;
        return Ok(Self::new(val));
    }

    /// XOR with round key
    pub fn mix_key(&self, key: u16) -> Self {
        return Self::new(self.val ^ key);
    }

    /// Get the bit at the specified location following big-endianness and
    /// 1-based indexing
    pub fn get_bit_1base(&self, loc: u8) -> Result<u16> {
        if loc < 1 || loc > 16 {
            return Err("loc must be between 1 and 16".into());
        }
        let mask = 1u16 << (16 - loc);
        if self.val & mask == 0 {
            return Ok(0);
        }
        return Ok(1);
    }

    /// Substitute each 4-bit block according to the input SBOX, then put the
    /// substituted blocks back together
    fn substitute(&self, sbox: &[(u16, u16)]) -> Result<Self> {
        let b0 = self.val % 16;
        let b1 = (self.val >> 4) % 16;
        let b2 = (self.val >> 8) % 16;
        let b3 = (self.val >> 12) % 16;

        let b0 = lookup(&sbox, b0)?;
        let b1 = lookup(&sbox, b1)?;
        let b2 = lookup(&sbox, b2)?;
        let b3 = lookup(&sbox, b3)?;

        let b3 = b3 << 12;
        let b2 = b2 << 8;
        let b1 = b1 << 4;

        return Ok(Self::new(b3 + b2 + b1 + b0));
    }

    /// Permute each bit according to the input permutation
    fn permute(&self, permutation: &[(u16, u16)]) -> Result<Self> {
        let mut val: u16 = 0;

        for shift in 0..16 {
            let mask = 1u16 << shift;
            if (self.val & mask) != 0 {
                let mapped = lookup(permutation, mask)?;
                val += mapped;
            }
        }

        return Ok(Self::new(val));
    }
}

/// Heys' block cipher
pub struct HeysCipher {
    round_keys: [u16; 5],
}

impl HeysCipher {
    pub fn from_keys(new_keys: &[u16]) -> Result<Self> {
        if new_keys.len() != 5 {
            return Err("Cipher requires exactly 5 round keys".into());
        }
        let mut round_keys: [u16; 5] = [0; 5];
        for i in 0..5 {
            round_keys[i] = new_keys[i];
        }
        return Ok(Self { round_keys });
    }

    pub fn encrypt(&self, plaintext: &Block) -> Result<Block> {
        let u1 = plaintext.mix_key(self.round_keys[0]);
        let v1 = u1.substitute(&SBOX)?;
        let u2 = v1.permute(&PERMUTATION)?.mix_key(self.round_keys[1]);
        let v2 = u2.substitute(&SBOX)?;
        let u3 = v2.permute(&PERMUTATION)?.mix_key(self.round_keys[2]);
        let v3 = u3.substitute(&SBOX)?;
        let u4 = v3.permute(&PERMUTATION)?.mix_key(self.round_keys[3]);
        let v4 = u4.substitute(&SBOX)?;

        return Ok(v4.mix_key(self.round_keys[4]));
    }

    pub fn decrypt(&self, ciphertext: &Block) -> Result<Block> {
        let v4 = ciphertext.mix_key(self.round_keys[4]);
        let u4 = v4.substitute(&SBOX_INVERT)?;
        let v3 = u4
            .mix_key(self.round_keys[3])
            .permute(&PERMUTATION_INVERT)?;
        let u3 = v3.substitute(&SBOX_INVERT)?;
        let v2 = u3
            .mix_key(self.round_keys[2])
            .permute(&PERMUTATION_INVERT)?;
        let u2 = v2.substitute(&SBOX_INVERT)?;
        let v1 = u2
            .mix_key(self.round_keys[1])
            .permute(&PERMUTATION_INVERT)?;
        let u1 = v1.substitute(&SBOX_INVERT)?;
        let pt = u1.mix_key(self.round_keys[0]);

        return Ok(pt);
    }

    /// A linear approximation takes the form:
    ///
    /// (some plaintext bits) + (some U4 bits) = 0 (mod 2)
    /// where U4 is the intermediary state and the bits are specified using
    /// big-endian, 1-based indexing.
    ///
    /// For example:
    /// U[4,6] + U[4,8] + U[4,14] + U[4,16] + P[5] + P[7] + P[8] == 0
    /// (this is stated in Heys' paper in section 3.4)
    ///
    /// User is responsible for making sure the input bit locs are valid
    pub fn check_linear_approx(
        &self,
        pt: &Block,
        ct: &Block,
        pt_locs: &[u8],
        u4_locs: &[u8],
    ) -> u16 {
        let mut binsum: u16 = 0;
        let u4 = ct
            .mix_key(self.round_keys[4])
            .substitute(&SBOX_INVERT)
            .unwrap();
        binsum += pt_locs
            .iter()
            .map(|loc| pt.get_bit_1base(*loc).unwrap())
            .sum::<u16>();
        binsum += u4_locs
            .iter()
            .map(|loc| u4.get_bit_1base(*loc).unwrap())
            .sum::<u16>();

        return 1 - binsum % 2;
    }

    /// Compute the bias of the input linear relation over the inputs PT-CT
    /// pairs
    pub fn get_bias(
        &self,
        plaintexts: &[Block],
        ciphertexts: &[Block],
        pt_locs: &[u8],
        u4_locs: &[u8],
    ) -> f64 {
        let sum = plaintexts
            .iter()
            .zip(ciphertexts.iter())
            .map(|(pt, ct)| self.check_linear_approx(pt, ct, pt_locs, u4_locs))
            .sum::<u16>();
        let prob = (sum as f64) / (plaintexts.len() as f64);
        if prob > 0.5 {
            return prob - 0.5;
        }
        return 0.5 - prob;
    }
}

/// Given in the input PT-CT pairs and the relationship specified by P-locs
/// U4-locs, return all possible K5 values, ranked by bias
pub fn brute_force_k5(
    plaintexts: &[Block],
    ciphertexts: &[Block],
    pt_locs: &[u8],
    u4_locs: &[u8],
    verbose: bool,
) -> Vec<(f64, u16)> {
    let mut rankings: Vec<(f64, u16)> = (u16::MIN..=u16::MAX)
        .map(|round_key| {
            if verbose {
                println!("{round_key}");
            }
            let cipher = HeysCipher::from_keys(&[0, 0, 0, 0, round_key]).unwrap();
            let bias = cipher.get_bias(plaintexts, ciphertexts, pt_locs, u4_locs);
            return (bias, round_key);
        })
        .collect::<Vec<(f64, u16)>>();
    rankings.sort_by(|elem1, elem2| {
        let (bias1, _) = elem1;
        let (bias2, _) = elem2;
        return bias2.partial_cmp(bias1).unwrap(); // reverse sort
    });
    return rankings;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cipher_correctness() {
        let cipher = HeysCipher::from_keys(&[1, 2, 3, 4, 5]).unwrap();
        for val in 0x0000u16..=0xffff {
            let pt = Block::new(val);
            let ct = cipher.encrypt(&pt).unwrap();
            assert_eq!(cipher.decrypt(&ct).unwrap(), pt);
        }
    }

    #[test]
    fn test_sbox() {
        let block = Block::new(0xabcd);
        assert_eq!(block.substitute(&SBOX).unwrap(), Block::new(0x6C59));
    }

    #[test]
    fn test_permutation() {
        assert_eq!(
            Block::new(0b1111000000000000)
                .permute(&PERMUTATION)
                .unwrap(),
            Block::new(0b1000100010001000)
        );
    }
}
