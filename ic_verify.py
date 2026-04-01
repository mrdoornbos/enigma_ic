#!/usr/bin/env python3
"""Index of coincidence attack on Enigma M3.
Verifies the IC approach before implementing on C64.

Michael Doornbos 2026
mike@imapenguin.com"""

import time
import sys

ROTORS = [
    "EKMFLGDQVZNTOWYHXUSPAIBRCJ",  # I
    "AJDKSIRUXBLHWTMCQGZNPYFVOE",  # II
    "BDFHJLCPRTXVZNYEIWGAKMUSQO",  # III
    "ESOVPZJAYQUIRHXLNFTGKDCMWB",  # IV
    "VZBRGITYUPSDNHLXAWMJQOFECK",  # V
    "JPGVOUMFYQBENHZRDKASXLICTW",  # VI
    "NZJHGRCXMYSWBOUFAIVLPEKQDT",  # VII
    "FKQHTLXOCBJSPDZRAMEWNIUYGV",  # VIII
]

REFLECTOR = "YRUHQSLDPXNGOKMIEBFZCWVJAT"

NOTCHES = [
    [16], [4], [21], [9], [25],
    [25, 12], [25, 12], [25, 12],
]

def make_wiring(s):
    return [ord(c) - 65 for c in s]

def make_inverse(fwd):
    inv = [0] * 26
    for i, v in enumerate(fwd):
        inv[v] = i
    return inv

class Enigma:
    def __init__(self, left, mid, right, lpos=0, mpos=0, rpos=0):
        self.left_sel = left
        self.mid_sel = mid
        self.right_sel = right
        self.left_pos = lpos
        self.mid_pos = mpos
        self.right_pos = rpos
        self.fwd = [make_wiring(r) for r in ROTORS]
        self.inv = [make_inverse(f) for f in self.fwd]
        self.ref = make_wiring(REFLECTOR)

    def step(self):
        mid_notch = NOTCHES[self.mid_sel]
        right_notch = NOTCHES[self.right_sel]
        if self.mid_pos in mid_notch:
            self.left_pos = (self.left_pos + 1) % 26
            self.mid_pos = (self.mid_pos + 1) % 26
        elif self.right_pos in right_notch:
            self.mid_pos = (self.mid_pos + 1) % 26
        self.right_pos = (self.right_pos + 1) % 26

    def rotor_pass(self, c, table, pos):
        c = (c + pos) % 26
        c = table[c]
        c = (c - pos + 26) % 26
        return c

    def encrypt_char(self, c):
        self.step()
        c = self.rotor_pass(c, self.fwd[self.right_sel], self.right_pos)
        c = self.rotor_pass(c, self.fwd[self.mid_sel], self.mid_pos)
        c = self.rotor_pass(c, self.fwd[self.left_sel], self.left_pos)
        c = self.ref[c]
        c = self.rotor_pass(c, self.inv[self.left_sel], self.left_pos)
        c = self.rotor_pass(c, self.inv[self.mid_sel], self.mid_pos)
        c = self.rotor_pass(c, self.inv[self.right_sel], self.right_pos)
        return c

    def process(self, text):
        return "".join(chr(self.encrypt_char(ord(c) - 65) + 65) for c in text)


def compute_ic(text):
    """Compute index of coincidence for a string of uppercase letters."""
    counts = [0] * 26
    for c in text:
        counts[ord(c) - 65] += 1
    n = len(text)
    if n < 2:
        return 0.0
    total = sum(c * (c - 1) for c in counts)
    return total / (n * (n - 1))


def compute_ic_sum(values):
    """Compute the numerator of IC (sum of n_i*(n_i-1)) for integer values 0-25."""
    counts = [0] * 26
    for v in values:
        counts[v] += 1
    return sum(c * (c - 1) for c in counts)


# --- Test setup ---

# Longer German plaintext for IC to work well
PLAINTEXT = "WETTERVORHERSAGEBISKAYAHEUTEREGENMITWINDSTAERKEFUENFAUSOSTEN"
# Known correct settings: III-I-V at M-C-Q (indices 2,0,4 at 12,2,16)
LEFT, MID, RIGHT = 2, 0, 4
LPOS, MPOS, RPOS = 12, 2, 16

print(f"Plaintext:  {PLAINTEXT}")
print(f"Length:     {len(PLAINTEXT)}")
print(f"Rotors:    III-I-V (indices {LEFT},{MID},{RIGHT})")
print(f"Positions: M-C-Q ({LPOS},{MPOS},{RPOS})")
print()

# Encrypt
e = Enigma(LEFT, MID, RIGHT, LPOS, MPOS, RPOS)
CIPHERTEXT = e.process(PLAINTEXT)
print(f"Ciphertext: {CIPHERTEXT}")

# Verify decryption
e2 = Enigma(LEFT, MID, RIGHT, LPOS, MPOS, RPOS)
decrypted = e2.process(CIPHERTEXT)
print(f"Decrypted:  {decrypted}")
print(f"Match:      {decrypted == PLAINTEXT}")
print()

# IC of the plaintext (German)
ic_plain = compute_ic(PLAINTEXT)
print(f"IC of plaintext (German):   {ic_plain:.4f}")
print(f"Expected German IC:         ~0.0667")
print(f"Expected random IC:         ~0.0385")

# IC of ciphertext (should be near random)
ic_cipher = compute_ic(CIPHERTEXT)
print(f"IC of ciphertext:           {ic_cipher:.4f}")
print()

# --- Test IC on correct vs wrong decryptions ---
print("=== IC of decryptions at various settings ===")
print()

# Correct settings
e3 = Enigma(LEFT, MID, RIGHT, LPOS, MPOS, RPOS)
dec3 = e3.process(CIPHERTEXT)
ic3 = compute_ic(dec3)
print(f"Correct (III-I-V, M-C-Q): IC = {ic3:.4f}  {dec3[:30]}...")

# A few wrong settings
for label, l, m, r, lp, mp, rp in [
    ("Wrong pos (III-I-V, A-A-A)", 2, 0, 4, 0, 0, 0),
    ("Wrong pos (III-I-V, M-C-R)", 2, 0, 4, 12, 2, 17),
    ("Wrong rotors (I-II-III, M-C-Q)", 0, 1, 2, 12, 2, 16),
    ("Wrong rotors (I-II-III, A-A-A)", 0, 1, 2, 0, 0, 0),
]:
    e4 = Enigma(l, m, r, lp, mp, rp)
    dec4 = e4.process(CIPHERTEXT)
    ic4 = compute_ic(dec4)
    print(f"{label}: IC = {ic4:.4f}  {dec4[:30]}...")

print()

# --- IC distribution over all positions for correct ordering ---
print("=== IC distribution for III-I-V, all 17,576 positions ===")
ics = []
for lp in range(26):
    for mp in range(26):
        for rp in range(26):
            e5 = Enigma(LEFT, MID, RIGHT, lp, mp, rp)
            dec5 = e5.process(CIPHERTEXT)
            ic5 = compute_ic(dec5)
            ics.append((ic5, lp, mp, rp))

ics.sort(reverse=True)
print(f"Top 10 IC values:")
for ic, lp, mp, rp in ics[:10]:
    pos = f"{chr(lp+65)}-{chr(mp+65)}-{chr(rp+65)}"
    e6 = Enigma(LEFT, MID, RIGHT, lp, mp, rp)
    dec6 = e6.process(CIPHERTEXT)
    print(f"  {pos}: IC = {ic:.4f}  {dec6[:40]}...")

# Find where correct answer ranks
for rank, (ic, lp, mp, rp) in enumerate(ics):
    if lp == LPOS and mp == MPOS and rp == RPOS:
        print(f"\nCorrect answer M-C-Q: rank {rank+1}, IC = {ic:.4f}")
        break

# Threshold analysis
print()
for threshold in [0.04, 0.045, 0.05, 0.055, 0.06]:
    count = sum(1 for ic, _, _, _ in ics if ic >= threshold)
    print(f"IC >= {threshold:.3f}: {count} candidates ({100*count/17576:.1f}%)")

# --- Integer threshold for C64 ---
N = len(PLAINTEXT)
print(f"\n=== Integer threshold for C64 (N={N}) ===")
print(f"N*(N-1) = {N*(N-1)}")
for threshold in [0.04, 0.045, 0.05, 0.055, 0.06]:
    int_thresh = int(threshold * N * (N - 1))
    print(f"IC >= {threshold:.3f} => sum >= {int_thresh}")

# Compute the IC sum (integer) for correct decryption
dec_correct = Enigma(LEFT, MID, RIGHT, LPOS, MPOS, RPOS).process(CIPHERTEXT)
values = [ord(c) - 65 for c in dec_correct]
ic_sum = compute_ic_sum(values)
print(f"\nCorrect decryption IC sum = {ic_sum}")
print(f"IC = {ic_sum}/{N*(N-1)} = {ic_sum/(N*(N-1)):.4f}")

# --- Full search (all 336 orderings x 17,576 positions) ---
if "--search" in sys.argv:
    print("\n=== Full IC search (5.9M candidates) ===")
    threshold = 0.05  # adjust based on distribution analysis
    int_thresh = int(threshold * N * (N - 1))
    print(f"Threshold: IC sum >= {int_thresh} (IC >= {threshold})")
    print()

    cipher_values = [ord(c) - 65 for c in CIPHERTEXT]
    hits = []
    total = 0
    t0 = time.time()

    for l in range(8):
        for m in range(8):
            if m == l:
                continue
            for r in range(8):
                if r == l or r == m:
                    continue
                for lp in range(26):
                    for mp in range(26):
                        for rp in range(26):
                            total += 1
                            # decrypt
                            e = Enigma(l, m, r, lp, mp, rp)
                            dec = [e.encrypt_char(c) for c in cipher_values]
                            ic_s = compute_ic_sum(dec)
                            if ic_s >= int_thresh:
                                pos = f"{chr(lp+65)}-{chr(mp+65)}-{chr(rp+65)}"
                                rotors = f"{l+1}-{m+1}-{r+1}"
                                text = "".join(chr(d+65) for d in dec)
                                hits.append((ic_s, rotors, pos, text))

    elapsed = time.time() - t0
    print(f"Searched {total:,} candidates in {elapsed:.1f}s")
    print(f"Hits: {len(hits)}")
    print()

    hits.sort(reverse=True)
    for ic_s, rotors, pos, text in hits[:20]:
        ic_val = ic_s / (N * (N - 1))
        print(f"  Rotors {rotors}, pos {pos}: IC={ic_val:.4f} sum={ic_s}  {text[:40]}...")

    # Check if correct answer is in hits
    found = False
    for ic_s, rotors, pos, text in hits:
        if rotors == "3-1-5" and pos == "M-C-Q":
            found = True
            print(f"\nCorrect answer found! Rank among {len(hits)} hits.")
            break
    if not found:
        print(f"\nCorrect answer NOT in hits! Try lower threshold.")
