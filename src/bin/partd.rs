use cryptanalysis::heys::{self, Block};
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
    let rankings = heys::brute_force_k5(
        &plaintexts,
        &ciphertexts,
        &[1, 4, 9, 12],
        &[2, 6, 10, 14],
        false,
    );

    rankings.iter().take(5).for_each(|(bias, round_key)| {
        println!("K5 candidate: 0x{round_key:04x}, observed bias: {bias:.6}");
    });
}
