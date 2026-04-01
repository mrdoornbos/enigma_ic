#!/usr/bin/env python3
"""Find top 10 IC candidates across all 336 orderings.

Michael Doornbos 2026
mike@imapenguin.com"""
from ic_verify import *

cipher_values = [ord(c) - 65 for c in CIPHERTEXT]
int_thresh = 194
hits = []

for l in range(8):
    for m in range(8):
        if m == l: continue
        for r in range(8):
            if r == l or r == m: continue
            for lp in range(26):
                for mp in range(26):
                    for rp in range(26):
                        e = Enigma(l, m, r, lp, mp, rp)
                        dec = [e.encrypt_char(c) for c in cipher_values]
                        ic_s = compute_ic_sum(dec)
                        if ic_s >= int_thresh:
                            rnames = ['I','II','III','IV','V','VI','VII','VIII']
                            rotors = f"{rnames[l]}-{rnames[m]}-{rnames[r]}"
                            pos = f"{chr(lp+65)}-{chr(mp+65)}-{chr(rp+65)}"
                            text = "".join(chr(d+65) for d in dec)
                            hits.append((ic_s, rotors, pos, text))

hits.sort(reverse=True)
print(f"Total candidates: {len(hits)}\n")
print(f"Top 10 by IC sum:")
print(f"{'#':>3} {'IC Sum':>6} {'Rotors':<12} {'Pos':<7} Decryption (first 50 chars)")
print("-" * 90)
for i, (ic_s, rotors, pos, text) in enumerate(hits[:10]):
    marker = " <-- CORRECT" if "WETTER" in text else ""
    print(f"{i+1:>3} {ic_s:>6} {rotors:<12} {pos:<7} {text[:50]}{marker}")

for i, (ic_s, rotors, pos, text) in enumerate(hits):
    if "WETTER" in text:
        print(f"\nCorrect answer rank: #{i+1} out of {len(hits)}")
        break
