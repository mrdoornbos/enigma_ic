# Enigma Index of Coincidence Attack

Breaking Enigma M3 without known plaintext using William Friedman's index of coincidence (1922). Searches all 5,905,536 rotor/position combinations and flags candidates whose decrypted output has letter frequency distributions consistent with German text.

Related article: https://imapenguin.com/2026/04/breaking-enigma-with-index-of-coincidence-on-a-commodore-64/

## Implementations

### Commodore 64 (6502 assembly)

`ic-tmp.asm` - Turbo Macro Pro / TMPx syntax. Assembles at `$c000`, runs with `sys 49152`. Searches all 336 rotor orderings and 17,576 positions each. Threshold 194 (IC >= 0.055). Prints candidates to screen. Takes about 82 hours on a stock NTSC C64.

Assemble with TMPx:
```
tmpx ic-tmp.asm -o ic.prg
```

Run in VICE:
```
x64sc -autostart ic.prg
```

### C (single-threaded)

`ic_fast.c` - Same algorithm in C. Prints candidates with IC sum >= 250 and summary stats.

```
cc -O3 -o ic_fast ic_fast.c
./ic_fast
```

### C (OpenMP, multi-core)

`ic_omp.c` - Parallelizes across rotor orderings using OpenMP.

```
cc -O3 -Xpreprocessor -fopenmp -I/opt/homebrew/opt/libomp/include -L/opt/homebrew/opt/libomp/lib -lomp -o ic_omp ic_omp.c
./ic_omp
```

### Metal GPU (macOS)

`ic_metal.m` - Runs all 5.9 million candidates as parallel GPU threads on Apple Silicon.

```
clang -O3 -framework Metal -framework Foundation -o ic_metal ic_metal.m
./ic_metal
```

### Python (verification)

`ic_verify.py` - Reference implementation for verifying correctness. Run with `--search` for the full search.

```
python3 ic_verify.py
python3 ic_verify.py --search
```

`top10.py` - Finds the top 10 candidates by IC sum across all orderings.

```
python3 top10.py
```

## Performance

| Version | Time | Speedup vs C64 |
|---------|------|----------------|
| C64 (6502 asm, 1 MHz) | 82 hours | 1x |
| C, single-threaded (-O3) | ~1.9s | 159,000x |
| C, OpenMP (all cores) | ~0.4s | 722,000x |
| Metal GPU (Apple M4) | ~0.04s | 7,569,000x |

All versions produce 18,165 candidates at threshold 194.

## The Ciphertext

60 characters intercepted from a U-boat in the Bay of Biscay. Encrypted with Enigma M3, rotors III-I-V at positions M-C-Q, no plugboard.

```
YDMAOIGMPQZPFVRCIGIIKJVECBDNPDITBYRYNKOCNJHIIVWXYUJBCDYGKVHW
```

Decrypts to: WETTERVORHERSAGEBISKAYAHEUTEREGENMITWINDSTAERKEFUENFAUSOSTEN

"Weather forecast Biscay, today rain with wind strength five from east."

## License

Public domain. Do what you want with it.
