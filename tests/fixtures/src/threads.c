// N threads each call thread_marker() once.
#include <pthread.h>
#include <stdio.h>
#include "labels.h"

#define THREADS 4

pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;
int done = 0;

__attribute__((noinline)) void thread_marker(long id) {
    pthread_mutex_lock(&lock);
    done++;
    pthread_mutex_unlock(&lock);
}

void *worker(void *argument) {
    thread_marker((long)argument);
    return NULL;
}

int main(void) {
    setvbuf(stdout, NULL, _IONBF, 0);
    pthread_t threads[THREADS];
    for (long i = 0; i < THREADS; i++)
        pthread_create(&threads[i], NULL, worker, (void *)i);
    for (int i = 0; i < THREADS; i++)
        pthread_join(threads[i], NULL);
    printf("done %d\n", done);
    return 0;
}
