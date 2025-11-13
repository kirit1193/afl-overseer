/* Simple test program for fuzzing */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

int main(int argc, char **argv) {
    char buffer[100];

    /* Read from stdin */
    if (read(0, buffer, sizeof(buffer) - 1) < 0) {
        return 1;
    }

    /* Simple vulnerability for demonstration */
    if (buffer[0] == 'A' && buffer[1] == 'F' && buffer[2] == 'L') {
        if (buffer[3] == '!') {
            /* Simulate a crash */
            abort();
        }
    }

    return 0;
}
