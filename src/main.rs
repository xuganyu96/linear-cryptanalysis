use cryptanalysis::heys::{Block, HeysCipher};

fn main() {
    let round_keys = [0, 0, 0, 0, 0];
    let cipher = HeysCipher::from_keys(&round_keys).unwrap();
    let plaintexts = (u16::MIN..=u16::MAX)
        .map(|val| Block::new(val))
        .collect::<Vec<Block>>();
    let ciphertexts = plaintexts
        .iter()
        .map(|pt| cipher.encrypt(pt).unwrap())
        .collect::<Vec<Block>>();

    let bias = cipher.get_bias(&plaintexts, &ciphertexts, &[5, 7, 8], &[6, 8, 14, 16]);
    println!("{bias}");
}
