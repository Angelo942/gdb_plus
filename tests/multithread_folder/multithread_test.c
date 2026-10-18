#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>

#define THREAD_COUNT 8
#define MAX_LEN 256

typedef struct {
    char chunk[MAX_LEN];
    char target[MAX_LEN];
    int thread_id;
    int *result_ptr;  // Pointer to store match result
} ThreadData;

void apply_inverse_permutation(char *chunk, const char *target) {
    int len = strlen(chunk);
    char temp[MAX_LEN];
    for (int i = 0; i < len; i++) {
        for (int j = 0; j < len; j++) {
            if (chunk[j] == target[i]) {
                temp[i] = chunk[j];
                chunk[j] = '\0';
                break;
            }
        }
    }
    temp[len] = '\0';
    strcpy(chunk, temp);
}

void* thread_function(void *arg) {
    ThreadData *data = (ThreadData*)arg;

    char shuffled[MAX_LEN];
    strcpy(shuffled, data->chunk);
    apply_inverse_permutation(shuffled, data->target);

    int match = strcmp(shuffled, data->target) == 0 ? 1 : 0;
    *(data->result_ptr) = match;

    pthread_exit(NULL);
}

void generate_scrambled_chunks(char chunks[THREAD_COUNT][MAX_LEN], const char *targets[THREAD_COUNT]) {
    const char *scrambled[THREAD_COUNT] = {
        "htm", "elu", "adx", "npi", "ale", "xeg", "itm", "aer"
    };
    for (int i = 0; i < THREAD_COUNT; i++) {
        strcpy(chunks[i], scrambled[i]);
    }
}

int main() {
    const char *known_targets[THREAD_COUNT] = {
        "mth", "ule", "xda", "inp", "lea", "gex", "mti", "rae"
    };

    pthread_t threads[THREAD_COUNT];
    ThreadData thread_data[THREAD_COUNT];
    char chunks[THREAD_COUNT][MAX_LEN];
    int match_flags[THREAD_COUNT] = {0};  // To collect results from threads

    generate_scrambled_chunks(chunks, known_targets);

    for (int i = 0; i < THREAD_COUNT; i++) {
        strcpy(thread_data[i].chunk, chunks[i]);
        strcpy(thread_data[i].target, known_targets[i]);
        thread_data[i].thread_id = i;
        thread_data[i].result_ptr = &match_flags[i];

        if (pthread_create(&threads[i], NULL, thread_function, &thread_data[i]) != 0) {
            perror("pthread_create failed");
            exit(1);
        }
    }

    for (int i = 0; i < THREAD_COUNT; i++) {
        pthread_join(threads[i], NULL);
    }

    // Final result check
    int all_matched = 1;
    for (int i = 0; i < THREAD_COUNT; i++) {
        if (match_flags[i] != 1) {
            all_matched = 0;
            break;
        }
    }

    if (all_matched) {
        printf("SUCCESS: All threads matched their targets.\n");
    } else {
        printf("FAILURE: One or more threads did not match their targets.\n");
    }

    return 0;
}
