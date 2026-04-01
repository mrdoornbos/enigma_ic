/* Enigma IC attack - Metal GPU version
 * Michael Doornbos 2026
 * mike@imapenguin.com */

#import <Foundation/Foundation.h>
#import <Metal/Metal.h>
#include <stdio.h>
#include <time.h>

static const char *metalSource = R"(
#include <metal_stdlib>
using namespace metal;

constant int ROTORS[8][26] = {
    {4,10,12,5,11,6,3,16,21,25,13,19,14,22,24,7,23,20,18,15,0,8,1,17,2,9},
    {0,9,3,10,18,8,17,20,23,1,11,7,22,19,12,2,16,6,25,13,15,24,5,21,14,4},
    {1,3,5,7,9,11,2,15,17,19,23,21,25,13,24,4,8,22,6,0,10,12,20,18,16,14},
    {4,18,14,21,15,25,9,0,24,16,20,8,17,7,23,11,13,5,19,6,10,3,2,12,22,1},
    {21,25,1,17,6,8,19,24,20,15,18,3,13,7,11,23,0,22,12,9,16,14,5,4,2,10},
    {9,15,6,21,14,20,12,5,24,16,1,4,13,7,25,17,3,10,0,18,23,11,8,2,19,22},
    {13,25,9,7,6,17,2,23,12,24,18,22,1,14,20,5,0,8,21,11,15,4,10,16,3,19},
    {5,10,16,7,19,11,23,14,2,1,9,18,15,3,25,17,0,12,4,22,13,8,20,24,6,21},
};

constant int INV[8][26] = {
    {20,22,24,6,0,3,5,15,21,25,1,4,2,10,12,19,7,23,18,11,17,8,13,16,14,9},
    {0,9,15,2,25,22,17,11,5,1,3,10,14,19,24,20,16,6,4,13,7,23,12,8,21,18},
    {19,0,6,1,15,2,18,3,16,4,20,5,21,13,25,7,24,8,23,9,22,11,17,10,14,12},
    {7,25,22,21,0,17,19,13,11,6,20,15,23,16,2,4,9,12,1,18,10,3,24,14,8,5},
    {16,2,24,11,23,22,4,13,5,19,25,14,18,12,21,9,20,3,10,6,8,0,17,15,7,1},
    {18,10,23,16,11,7,2,13,22,0,17,21,6,12,4,1,9,15,19,24,5,3,25,20,8,14},
    {16,12,6,24,21,15,4,3,17,2,22,19,8,0,13,20,23,5,10,25,14,18,11,7,9,1},
    {16,9,8,13,18,0,24,3,21,10,1,5,17,20,7,12,2,15,11,4,22,25,19,6,23,14},
};

constant int REFLECTOR[26] = {
    24,17,20,7,16,18,11,3,15,23,13,6,14,10,12,8,4,1,5,25,2,22,21,9,0,19
};

constant int NOTCH1[8] = {16,4,21,9,25,25,25,25};
constant int NOTCH2[8] = {-1,-1,-1,-1,-1,12,12,12};

constant int CIPHER[60] = {
    24,3,12,0,14,8,6,12,15,16,25,15,5,21,17,2,8,6,8,8,10,9,21,4,
    2,1,3,13,15,3,8,19,1,24,17,24,13,10,14,2,13,9,7,8,8,21,22,23,
    24,20,9,1,2,3,24,6,10,21,7,22
};

inline int mod26(int v) {
    return v >= 26 ? v - 26 : v;
}

inline int rotor_pass(int c, constant const int *table, int pos) {
    c = mod26(c + pos);
    c = table[c];
    c = mod26(c - pos + 26);
    return c;
}

struct Ordering {
    int l, m, r;
};

kernel void ic_search(
    constant Ordering *orderings [[buffer(0)]],
    device atomic_int *hit_count [[buffer(1)]],
    uint gid [[thread_position_in_grid]]
) {
    int nord = 336;
    int ord_idx = gid / 17576;
    int pos_idx = gid % 17576;
    if (ord_idx >= nord) return;

    int tl = orderings[ord_idx].l;
    int tm = orderings[ord_idx].m;
    int tr = orderings[ord_idx].r;

    int lp0 = pos_idx / 676;
    int mp0 = (pos_idx / 26) % 26;
    int rp0 = pos_idx % 26;

    constant const int *rf_l = ROTORS[tl];
    constant const int *rf_m = ROTORS[tm];
    constant const int *rf_r = ROTORS[tr];
    constant const int *ri_l = INV[tl];
    constant const int *ri_m = INV[tm];
    constant const int *ri_r = INV[tr];
    int n1_m0 = NOTCH1[tm], n1_m1 = NOTCH2[tm];
    int n1_r0 = NOTCH1[tr], n1_r1 = NOTCH2[tr];

    int lp = lp0, mp = mp0, rp = rp0;
    int freq[26] = {};

    for (int i = 0; i < 60; i++) {
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
        freq[c]++;
    }

    int ic_sum = 0;
    for (int i = 0; i < 26; i++)
        ic_sum += freq[i] * (freq[i] - 1);

    if (ic_sum >= 194)
        atomic_fetch_add_explicit(hit_count, 1, memory_order_relaxed);
}
)";

int main(void) {
    @autoreleasepool {
        id<MTLDevice> device = MTLCreateSystemDefaultDevice();
        if (!device) { fprintf(stderr, "No Metal device\n"); return 1; }
        printf("GPU: %s\n", [[device name] UTF8String]);

        NSError *error = nil;
        MTLCompileOptions *opts = [[MTLCompileOptions alloc] init];
        id<MTLLibrary> library = [device newLibraryWithSource:
            [NSString stringWithUTF8String:metalSource] options:opts error:&error];
        if (!library) {
            fprintf(stderr, "Compile error: %s\n", [[error description] UTF8String]);
            return 1;
        }

        id<MTLFunction> func = [library newFunctionWithName:@"ic_search"];
        id<MTLComputePipelineState> pipeline =
            [device newComputePipelineStateWithFunction:func error:&error];
        if (!pipeline) {
            fprintf(stderr, "Pipeline error: %s\n", [[error description] UTF8String]);
            return 1;
        }

        /* build orderings */
        typedef struct { int l, m, r; } Ordering;
        Ordering ords[336];
        int nord = 0;
        for (int l = 0; l < 8; l++)
        for (int m = 0; m < 8; m++) {
            if (m == l) continue;
            for (int r = 0; r < 8; r++) {
                if (r == l || r == m) continue;
                ords[nord++] = (Ordering){l, m, r};
            }
        }

        int total_threads = 336 * 17576; /* 5,905,536 */

        id<MTLBuffer> ordBuf = [device newBufferWithBytes:ords
            length:sizeof(ords) options:MTLResourceStorageModeShared];
        id<MTLBuffer> hitBuf = [device newBufferWithLength:sizeof(int)
            options:MTLResourceStorageModeShared];
        *(int *)[hitBuf contents] = 0;

        id<MTLCommandQueue> queue = [device newCommandQueue];
        id<MTLCommandBuffer> cmdBuf = [queue commandBuffer];
        id<MTLComputeCommandEncoder> encoder = [cmdBuf computeCommandEncoder];

        [encoder setComputePipelineState:pipeline];
        [encoder setBuffer:ordBuf offset:0 atIndex:0];
        [encoder setBuffer:hitBuf offset:0 atIndex:1];

        NSUInteger threadGroupSize = pipeline.maxTotalThreadsPerThreadgroup;
        if (threadGroupSize > 256) threadGroupSize = 256;
        MTLSize gridSize = MTLSizeMake(total_threads, 1, 1);
        MTLSize groupSize = MTLSizeMake(threadGroupSize, 1, 1);

        struct timespec t0, t1;
        clock_gettime(CLOCK_MONOTONIC, &t0);

        [encoder dispatchThreads:gridSize threadsPerThreadgroup:groupSize];
        [encoder endEncoding];
        [cmdBuf commit];
        [cmdBuf waitUntilCompleted];

        clock_gettime(CLOCK_MONOTONIC, &t1);
        double elapsed = (t1.tv_sec - t0.tv_sec) + (t1.tv_nsec - t0.tv_nsec) / 1e9;

        int hits = *(int *)[hitBuf contents];

        printf("Candidates: %d\n", total_threads);
        printf("Hits (IC >= 194): %d\n", hits);
        printf("Time: %.3f seconds\n", elapsed);
        printf("Candidates/sec: %.0f\n", total_threads / elapsed);
    }
    return 0;
}
