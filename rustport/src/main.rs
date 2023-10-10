use std::fs;
use std::error::Error;

type Result<T> = core::result::Result<T, Box<dyn Error>>;

#[allow(dead_code)]
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

fn sbox_lookup(sbox: &[(u16, u16)], val: u16) -> Result<u16> {
    for (from, to) in sbox {
        if *from == val {
            return Ok(*to);
        }
    }
    return Err("Lookup failed".into());
}

/// A 16-bit block
struct Block {
    val: u16,
}

impl Block {
    fn new(val: u16) -> Self {
        return Self {val };
    }

    fn from_binstr(binstr: &str) -> Result<Self> {
        let val = u16::from_str_radix(binstr, 2)?;
        return Ok(Self::new(val));
    }

    fn mix_key(&self, key: u16) -> Self {
        return Self::new(self.val ^ key);
    }

    fn get_bit_1base(&self, loc: usize) -> Result<u16> {
        if loc < 1 || loc > 16 {
            return Err("loc must be between 1 and 16".into());
        }
        let mask = 1u16 << (16 - loc);
        if self.val & mask == 0 {
            return Ok(0);
        }
        return Ok(1);
    }

    fn substitute(&self, sbox: &[(u16, u16)]) -> Result<Self> {
        let b0 = self.val % 16;
        let b1 = (self.val >> 4) % 16;
        let b2 = (self.val >> 8) % 16;
        let b3 = (self.val >> 12) % 16;

        let b0 = sbox_lookup(&sbox, b0)?;
        let b1 = sbox_lookup(&sbox, b1)?;
        let b2 = sbox_lookup(&sbox, b2)?;
        let b3 = sbox_lookup(&sbox, b3)?;

        let b3 = b3 << 12;
        let b2 = b2 << 8;
        let b1 = b1 << 4;

        return Ok(Self::new(b3 + b2 + b1 + b0));
    }
}

fn check_linear_approx(
    pt: &Block,
    ct: &Block,
    key: u16
) -> u16 {
    let u4 = ct.mix_key(key);
    let u4 = u4.substitute(&SBOX_INVERT).unwrap();

    let binsum = u4.get_bit_1base(2).unwrap()
        + u4.get_bit_1base(6).unwrap()
        + u4.get_bit_1base(10).unwrap()
        + u4.get_bit_1base(14).unwrap()
        + pt.get_bit_1base(1).unwrap()
        + pt.get_bit_1base(4).unwrap()
        + pt.get_bit_1base(9).unwrap()
        + pt.get_bit_1base(12).unwrap();
    return 1 - (binsum % 2);
}

fn compute_bias(plaintexts: &[Block], ciphertexts: &[Block], key: u16) -> f64 {
    let count = plaintexts.iter().zip(ciphertexts.iter())
        .map(|(pt, ct)| check_linear_approx(pt, ct, key))
        .sum::<u16>();
    let prob = (count as f64) / (plaintexts.len() as f64);
    if prob > 0.5 {
        return prob - 0.5;
    }
    return 0.5 - prob;
}

fn main() {
    let plaintexts = fs::read_to_string(
        "/Users/ganyuxu/opensource/waterloo-cryptography/co687/inputs/a2q1plaintexts.txt"
    ).unwrap().lines()
        .map(|line| Block::from_binstr(line).unwrap())
        .collect::<Vec<Block>>();
    let ciphertexts = fs::read_to_string(
        "/Users/ganyuxu/opensource/waterloo-cryptography/co687/inputs/a2q1ciphertexts.txt"
    ).unwrap().lines()
        .map(|line| Block::from_binstr(line).unwrap())
        .collect::<Vec<Block>>();

    let mut guesses: Vec<(f64, u16)> = vec![];
    for round_key in 0u16..=0xffffu16 {
        let bias = compute_bias(
            &plaintexts,
            &ciphertexts,
            round_key,
        );
        // println!("{round_key}: {bias}");
        guesses.push((bias, round_key));
    }

    guesses.sort_by(|a, b| {
        let (bias1, _) = a;
        let (bias2, _) = b;
        return bias2.partial_cmp(bias1).unwrap();
    });

    guesses.iter().take(5)
        .for_each(|(bias, round_key)| {
            println!("round key: {round_key:16b}, bias: {bias:08}");
        });
}
