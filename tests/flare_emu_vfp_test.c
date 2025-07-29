#include <stdio.h>

#define VECTOR_SIZE 4

void vector_add(float *a, float *b, float *result) {
    for (int i = 0; i < VECTOR_SIZE; i++) {
        result[i] = a[i] + b[i];
    }
}

int main() {
    float a[VECTOR_SIZE] = {1.5f, 2.5f, 3.5f, 4.5f};
    float b[VECTOR_SIZE] = {5.0f, 6.0f, 7.0f, 8.0f};
    float result[VECTOR_SIZE];

    vector_add(a, b, result);

    printf("Result of vector addition:\n");
    for (int i = 0; i < VECTOR_SIZE; i++) {
        printf("%.2f ", result[i]);
    }
    printf("\n");

    return 0;
}
