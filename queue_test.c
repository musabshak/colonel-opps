#include "queue.h"

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>

typedef struct Person {

    char name[50];
    int age;
} person_t;

void print_person(void *elementp) {
    person_t *person = (person_t *)elementp;
    printf("name: %s, age: %d\n", person->name, person->age);
}

bool search_by_age(void *elementp, const void *keyp) {
    person_t *person = (person_t *)elementp;

    if (person->age == (uintptr_t)keyp) {
        return true;
    } else {
        return false;
    }
}

int main(void) {

    // Create queue
    queue_t *qp = qopen();

    // Create people
    person_t person_1 = {.name = "musab", .age = 23};
    person_t person_2 = {.name = "varun", .age = 23};
    person_t person_3 = {.name = "katrina", .age = 23};

    // Put people in queue
    qput(qp, &person_1);
    qput(qp, &person_2);
    qput(qp, &person_3);

    // Check that people are in queue
    qapply(qp, print_person);
    printf("----------\n\n");

    // Test qremove_all
    qremove_all(qp, search_by_age, (const void *)23);

    qapply(qp, print_person);
}