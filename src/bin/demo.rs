use cryptanalysis::heys::{brute_force_k5, Block, HeysCipher};
use rand::{rngs::StdRng, Rng, SeedableRng};

fn generate_cipher(seed: u64) -> HeysCipher {
    let mut rng = StdRng::seed_from_u64(seed);
    let mut round_keys = [0; 5];
    for round in 0..5 {
        round_keys[round] = rng.gen();
    }
    println!("K5 is 0x{:04x}", round_keys[4]);
    return HeysCipher::from_keys(&round_keys).unwrap();
}

fn main() {
    // Over all 65536 possible pairs of PT-CT, the expected bias is 0.03125 (1/32)
    let cipher = generate_cipher(0);
    let plaintexts = (u16::MIN..=u16::MAX)
        .map(|val| Block::new(val))
        .collect::<Vec<Block>>();
    let ciphertexts = plaintexts
        .iter()
        .map(|pt| cipher.encrypt(pt).unwrap())
        .collect::<Vec<Block>>();

    // Use the generated PT/CT to brute-force all possible K5 candidates
    let rankings = brute_force_k5(
        &plaintexts,
        &ciphertexts,
        &[5, 7, 8],
        &[6, 8, 14, 16],
        false,
    );
    rankings.iter().take(5).for_each(|(bias, round_key)| {
        println!("K5 candidate: 0x{round_key:04x}, observed bias: {bias:.6}");
    });

    // Use the generated PT/CT to brute-force all possible K5 candidates
    let rankings = brute_force_k5(
        &plaintexts.get(0..1000).unwrap(),
        &ciphertexts.get(0..1000).unwrap(),
        &[1, 4, 9, 12],
        &[2, 6, 10, 14],
        false,
    );
    rankings.iter().take(5).for_each(|(bias, round_key)| {
        println!("K5 candidate: 0x{round_key:04x}, observed bias: {bias:.6}");
    });
}
