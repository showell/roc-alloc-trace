// A program roc-alloc-trace must refuse: it has roc_alloc and the rest, as
// a Roc program does, and starts a thread (tests/run.sh, "threads"), or with
// `fork` as its argument, a process.
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

__attribute__((noinline)) void *roc_alloc(size_t size, unsigned alignment) {
    (void)alignment;
    return malloc(size);
}

__attribute__((noinline)) void *roc_realloc(void *p, size_t size, size_t old, unsigned alignment) {
    (void)old;
    (void)alignment;
    return realloc(p, size);
}

__attribute__((noinline)) void roc_dealloc(void *p, unsigned alignment) {
    (void)alignment;
    free(p);
}

static void *work(void *arg) {
    roc_dealloc(roc_alloc(16, 8), 8);
    return arg;
}

int main(int argc, char **argv) {
    roc_dealloc(roc_realloc(roc_alloc(8, 8), 32, 8, 8), 8);
    if (argc > 1 && strcmp(argv[1], "fork") == 0) {
        pid_t pid = fork();
        if (pid == 0) _exit(0);
        waitpid(pid, NULL, 0);
        return 0;
    }
    pthread_t t;
    if (pthread_create(&t, NULL, work, NULL) != 0) return 1;
    pthread_join(t, NULL);
    return 0;
}
