#include <stdio.h>

int main() {
    int n;

    do {
        printf("Enter a positive integer: ");
        scanf("%d", &n);

        if (n <= 0) {
            printf("Invalid input. Please enter a positive integer.\n");
        }
    } while (n <= 0);

    printf("You entered: %d\n", n);

    return 0;
}