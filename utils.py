from boxes import *


def encrypt(msg, key):
    key = permutation_by_table(key, 64, PC1)  # 64bit -> PC1 -> 56bit

    # split up key in two halves
    # generate the 16 round keys
    C0 = key >> 28
    D0 = key & (2 ** 28 - 1)

    round_keys = generate_round_key(C0, D0)

    msg_block = permutation_by_table(msg, 64, IP)
    L0 = msg_block >> 32
    R0 = msg_block & (2 ** 32 - 1)

    L_round = R0
    R_round = L0 ^ round_function(R0, round_keys)

    cipher_block = (R_round << 32) + L_round

    # final permutation
    cipher_block = permutation_by_table(cipher_block, 64, IP_INV)

    return cipher_block


def round_function(Ri, Ki):
    # expand Ri from 32 to 48 bit using table E
    Ri = permutation_by_table(Ri, 32, E)

    # xor with round key
    Ri ^= Ki

    # split Ri into 8 groups of 6 bit
    Ri_blocks = [((Ri & (0b111111 << shift_val)) >> shift_val) for shift_val in (42, 36, 30, 24, 18, 12, 6, 0)]

    # interpret each block as address for the S-boxes
    for i, block in enumerate(Ri_blocks):
        # grab the bits we need
        row = ((0b100000 & block) >> 4) + (0b1 & block)
        col = (0b011110 & block) >> 1
        # sboxes are stored as one-dimensional tuple, so we need to calc the index this way
        Ri_blocks[i] = Sboxes[i][16 * row + col]

    # pack the blocks together again by concatenating
    Ri_blocks = zip(Ri_blocks, (28, 24, 20, 16, 12, 8, 4, 0))

    Ri = 0
    for block, lshift_val in Ri_blocks:
        Ri += (block << lshift_val)

    # another permutation 32bit -> 32bit
    Ri = permutation_by_table(Ri, 32, P)

    return Ri


def permutation_by_table(block, block_len: int, table: tuple):
    block_str = bin(block)[2:].zfill(block_len)

    perm = [block_str[table[pos] - 1] for pos in range(len(table))]

    return int(''.join(perm), 2)


def generate_round_key(C0, D0):
    def lrot(val, r_bits, max_bits):
        return (val << r_bits % max_bits) & (2 ** max_bits - 1) | \
                                         ((val & (2 ** max_bits - 1)) >> (max_bits - (r_bits % max_bits)))

    C0 = lrot(C0, 0, 28)
    D0 = lrot(D0, 0, 28)

    K = (C0 << 28) + D0
    round_key = permutation_by_table(K, 56, PC2)  # 56bit -> 48bit

    return round_key
