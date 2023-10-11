use cryptanalysis::heys::{HeysCipher, Block};
use std::fs;

fn read_inputs(path: &str) -> Vec<Block> {
    return fs::read_to_string(path)
        .unwrap()
        .lines()
        .map(|line| Block::from_binstr(line).unwrap())
        .collect::<Vec<Block>>();
}

fn main() {
    let plaintexts = read_inputs(
        "./inputs/a2q1plaintexts.txt",
    );
    let ciphertexts = read_inputs(
        "./inputs/a2q1ciphertexts.txt",
    );

    let mut rankings: Vec<(f64, u16)> = vec![];
    for bits_5_to_8 in 0b0000u16..=0b1111 {
        for bits_13_to_16 in 0b0000u16..=0b1111 {
            let round_key = (bits_5_to_8 << 8) + bits_13_to_16;
            let guess = HeysCipher::from_keys(&[0, 0, 0, 0, round_key]).unwrap();
            let bias = guess.get_bias(&plaintexts, &ciphertexts, &[5, 7, 8], &[6, 8, 14, 16]);
            rankings.push((bias, round_key));
        }
    }

    rankings.sort_by(|elem1, elem2| {
        let (bias1, _) = elem1;
        let (bias2, _) = elem2;
        return bias2.partial_cmp(bias1).unwrap();
    });
    rankings.iter().take(5)
        .for_each(|(bias, round_key)| {
            println!("K5 candidate: 0x{round_key:04x}, observed bias: {bias:.6}");
        });
}
