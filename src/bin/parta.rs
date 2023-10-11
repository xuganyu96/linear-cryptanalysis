use cryptanalysis::heys::{Block, HeysCipher};
use std::fs;

fn read_inputs(path: &str) -> Vec<Block> {
    return fs::read_to_string(path)
        .unwrap()
        .lines()
        .map(|line| Block::from_binstr(line).unwrap())
        .collect::<Vec<Block>>();
}

fn main() {
    let plaintexts = read_inputs("./inputs/a2q1plaintexts.txt");
    let ciphertexts = read_inputs("./inputs/a2q1ciphertexts.txt");
    let guess = HeysCipher::from_keys(&[0, 0, 0, 0, 0b0000011100000110]).unwrap();

    let bias = guess.get_bias(&plaintexts, &ciphertexts, &[5, 7, 8], &[6, 8, 14, 16]);
    println!("bias: {bias:.08}");
}
