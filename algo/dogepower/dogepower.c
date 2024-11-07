#include "yespower.h"
#include "algo-gate-api.h"
#include <string.h>


yespower_params_t dogepower_params = { .version = YESPOWER_1_0, .N = 2048, .r = 32, .pers = NULL, .perslen = 0 };

int dogepower_hash(const char *input, char *output, int thr_id) {
    // Use yespower_tls from yespower.c
    return yespower_tls((const uint8_t*)input, 80, &dogepower_params, (yespower_binary_t*)output, thr_id);
}

int scanhash_dogepower(struct work *work, uint32_t max_nonce, uint64_t *hashes_done, struct thr_info *mythr) {
    uint32_t _ALIGN(64) vhash[8];
    uint32_t _ALIGN(64) endiandata[20];
    uint32_t *pdata = work->data;
    uint32_t *ptarget = work->target;
    const uint32_t first_nonce = pdata[19];
    const uint32_t last_nonce = max_nonce;
    uint32_t n = first_nonce;
    const int thr_id = mythr->id;

    // Convert work data to big-endian format
    for (int k = 0; k < 19; k++) {
        be32enc(&endiandata[k], pdata[k]);
    }
    endiandata[19] = n;

    // Main nonce search loop
    do {
        // Hash data with current nonce and thread ID
        if (dogepower_hash((char*)endiandata, (char*)vhash, thr_id) == 0) {
            // Check if the hash meets the target
            if (valid_hash(vhash, ptarget) && !opt_benchmark) {
                be32enc(pdata + 19, n); // Update nonce in pdata
                submit_solution(work, vhash, mythr); // Submit the valid solution
                break;
            }
        }

        // Increment nonce and update endiandata
        endiandata[19] = ++n;

    } while (n < last_nonce && !work_restart[thr_id].restart);

    *hashes_done = n - first_nonce;
    pdata[19] = n;
    return 0;
}

bool register_dogepower_algo(algo_gate_t *gate) {
    yespower_params_t dogepower_params = {
        .version = YESPOWER_1_0,
        .N = 2048,
        .r = 32,
        .pers = NULL,
        .perslen = 0
    };

    gate->optimizations = SSE2_OPT | SHA256_OPT | NEON_OPT;
    gate->scanhash = (void *)&scanhash_dogepower;
#if defined(__SSE2__) || defined(__aarch64__)
    gate->hash = (void *)&dogepower_hash;
#else
    gate->hash = (void *)&dogepower_hash_ref;
#endif
    opt_target_factor = 65536.0;
    return true;
}
