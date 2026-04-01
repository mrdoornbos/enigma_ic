/* Enigma IC attack - single-threaded C version
 * Michael Doornbos 2026
 * mike@imapenguin.com */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

static const int ROTORS[8][26] = {
    {4,10,12,5,11,6,3,16,21,25,13,19,14,22,24,7,23,20,18,15,0,8,1,17,2,9},
    {0,9,3,10,18,8,17,20,23,1,11,7,22,19,12,2,16,6,25,13,15,24,5,21,14,4},
    {1,3,5,7,9,11,2,15,17,19,23,21,25,13,24,4,8,22,6,0,10,12,20,18,16,14},
    {4,18,14,21,15,25,9,0,24,16,20,8,17,7,23,11,13,5,19,6,10,3,2,12,22,1},
    {21,25,1,17,6,8,19,24,20,15,18,3,13,7,11,23,0,22,12,9,16,14,5,4,2,10},
    {9,15,6,21,14,20,12,5,24,16,1,4,13,7,25,17,3,10,0,18,23,11,8,2,19,22},
    {13,25,9,7,6,17,2,23,12,24,18,22,1,14,20,5,0,8,21,11,15,4,10,16,3,19},
    {5,10,16,7,19,11,23,14,2,1,9,18,15,3,25,17,0,12,4,22,13,8,20,24,6,21},
};

static int INV[8][26];

static const int REFLECTOR[26] = {
    24,17,20,7,16,18,11,3,15,23,13,6,14,10,12,8,4,1,5,25,2,22,21,9,0,19
};

static const int NOTCH1[8] = {16,4,21,9,25,25,25,25};
static const int NOTCH2[8] = {-1,-1,-1,-1,-1,12,12,12};

static const int CIPHER[60] = {
    24,3,12,0,14,8,6,12,15,16,25,15,5,21,17,2,8,6,8,8,10,9,21,4,
    2,1,3,13,15,3,8,19,1,24,17,24,13,10,14,2,13,9,7,8,8,21,22,23,
    24,20,9,1,2,3,24,6,10,21,7,22
};

static inline int mod26(int v) {
    return v >= 26 ? v - 26 : v;
}

static inline int rotor_pass(int c, const int *table, int pos) {
    c = mod26(c + pos);
    c = table[c];
    c = mod26(c - pos + 26);
    return c;
}

int main(void) {
    /* build inverse tables */
    for (int r = 0; r < 8; r++)
        for (int i = 0; i < 26; i++)
            INV[r][ROTORS[r][i]] = i;

    int threshold = 194;
    int total_candidates = 0;
    int hits = 0;

    struct timespec t0, t1;
    clock_gettime(CLOCK_MONOTONIC, &t0);

    for (int tl = 0; tl < 8; tl++) {
    for (int tm = 0; tm < 8; tm++) {
        if (tm == tl) continue;
    for (int tr = 0; tr < 8; tr++) {
        if (tr == tl || tr == tm) continue;

        const int *rf_l = ROTORS[tl], *rf_m = ROTORS[tm], *rf_r = ROTORS[tr];
        const int *ri_l = INV[tl], *ri_m = INV[tm], *ri_r = INV[tr];
        int n1_m0 = NOTCH1[tm], n1_m1 = NOTCH2[tm];
        int n1_r0 = NOTCH1[tr], n1_r1 = NOTCH2[tr];

        for (int lp0 = 0; lp0 < 26; lp0++) {
        for (int mp0 = 0; mp0 < 26; mp0++) {
        for (int rp0 = 0; rp0 < 26; rp0++) {
            total_candidates++;

            int lp = lp0, mp = mp0, rp = rp0;
            int freq[26] = {0};

            for (int i = 0; i < 60; i++) {
                /* step */
                if (mp == n1_m0 || mp == n1_m1) {
                    lp = mod26(lp + 1);
                    mp = mod26(mp + 1);
                } else if (rp == n1_r0 || rp == n1_r1) {
                    mp = mod26(mp + 1);
                }
                rp = mod26(rp + 1);

                /* encrypt */
                int c = CIPHER[i];
                c = rotor_pass(c, rf_r, rp);
                c = rotor_pass(c, rf_m, mp);
                c = rotor_pass(c, rf_l, lp);
                c = REFLECTOR[c];
                c = rotor_pass(c, ri_l, lp);
                c = rotor_pass(c, ri_m, mp);
                c = rotor_pass(c, ri_r, rp);
                freq[c]++;
            }

            /* IC sum */
            int ic_sum = 0;
            for (int i = 0; i < 26; i++)
                ic_sum += freq[i] * (freq[i] - 1);

            if (ic_sum >= threshold) {
                hits++;
                if (ic_sum >= 250) {
                    printf("Rotors %d-%d-%d  Pos %c-%c-%c  IC=%d  ",
                        tl+1, tm+1, tr+1,
                        lp0+'A', mp0+'A', rp0+'A', ic_sum);
                    /* decrypt again for display */
                    lp = lp0; mp = mp0; rp = rp0;
                    for (int i = 0; i < 40; i++) {
                        if (mp == n1_m0 || mp == n1_m1) {
                            lp = mod26(lp + 1); mp = mod26(mp + 1);
                        } else if (rp == n1_r0 || rp == n1_r1) {
                            mp = mod26(mp + 1);
                        }
                        rp = mod26(rp + 1);
                        int c = CIPHER[i];
                        c = rotor_pass(c, rf_r, rp);
                        c = rotor_pass(c, rf_m, mp);
                        c = rotor_pass(c, rf_l, lp);
                        c = REFLECTOR[c];
                        c = rotor_pass(c, ri_l, lp);
                        c = rotor_pass(c, ri_m, mp);
                        c = rotor_pass(c, ri_r, rp);
                        putchar(c + 'A');
                    }
                    putchar('\n');
                }
            }
        }}}
    }}}

    clock_gettime(CLOCK_MONOTONIC, &t1);
    double elapsed = (t1.tv_sec - t0.tv_sec) + (t1.tv_nsec - t0.tv_nsec) / 1e9;

    printf("\nCandidates: %d\n", total_candidates);
    printf("Hits (IC >= %d): %d\n", threshold, hits);
    printf("Time: %.3f seconds\n", elapsed);
    printf("Candidates/sec: %.0f\n", total_candidates / elapsed);

    return 0;
}
