# linear-cryptanalysis
A Python implementation of the tutorial written by Howard Heys: https://www.engr.mun.ca/~howard/PAPERS/ldc_tutorial.pdf


## Implement bit-wise permutation in Python
Bit-wise permutation (e.g. for each 8-bit block, map bit 0 to bit 7, bit 1 to bit 5, etc.) is non-trivial to implement on a software level since bits are packed into bytes and there is no immediate way of accessing the individual bits.

A naive implementation would be to first convert the number into a list of 1's and 0's, perform the permutation, then convert the list of 1's and 0's back into an integer. Although this would be correct, it would also be terribly inefficient (especially in Python) as `list` will probably incur allocation of heap memory and such.

Thanks to [this post](https://stackoverflow.com/questions/72685649/general-algorithm-for-bit-permutations), we can implement a good compromise between hard-coding (favors performance) and arithmetics (favors readability) using bit decomposition and a lookup table for the individual bits:

1. Decompose the integer into sum of powers of 2. Each power of 2 is represent a single "bit"
2. Define a lookup table that maps one power of 2 to another power of 2. This defines the permutation (which bit moves where)
3. Map the components of the decomposition using the lookup table, then sum them back.

Here is a sample implementation:

```python
LOOKUP = {
    0b00000001: 0b10000000,
    0b10000000: 0b00000001,
}

def bitdecomp(n: int):
    power = 1

    while n != 0:
        if n % 2 == 1:
            yield power
        n = n // 2
        power = power * 2

def bitpermute(n: int, lookup: dict):
    permuted = 0
    for bit in bitdecomp(n):
        permuted += lookup.get(bit, bit)
    return permuted
```

In fact, we can generalize beyond base 2 (although bases that are powers of 2 are probably a lot more prevalent and useful).

```python
def basedecomp(n: int, base: int):
    power = 1

    while n != 0:
        if n % base > 0:
            yield power
        n = n // base
        power = power * base
```