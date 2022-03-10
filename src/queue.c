/* queue.c -- A generic queue implementation
 *
 * Author: Musab Shakeel
 * Date: Fall 2019
 *
 * Refer to the queue.h interface for function documentation.
 *
 */

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

typedef struct queue {
    struct node *front;
    struct node *back;
} queue_t;

typedef struct node {
    void *data;
    struct node *next;
} node_t;

node_t *data_to_node(void *elementp) {
    node_t *nodep;
    if (!(nodep = (node_t *)malloc(sizeof(node_t)))) {
        return NULL;
    }
    nodep->data = elementp;
    nodep->next = NULL;
    return nodep;
}

queue_t *qopen(void) {
    queue_t *qp;
    if (!(qp = (queue_t *)malloc(sizeof(queue_t)))) {
        return NULL;
    }
    qp->front = NULL;
    qp->back = NULL;
    return qp;
}

void qclose(queue_t *qp) {
    node_t *n = qp->front;
    node_t *temp;
    while (n != NULL) {
        temp = n;
        n = n->next;
        free(temp);
    }
    free(qp);
}

bool qis_empty(queue_t *qp) {
    if (qp->front == qp->back && qp->back == NULL) {
        return true;
    }

    return false;
}

// cs58 addition
int qlen(queue_t *qp) {

    int len = 0;

    if (qis_empty(qp)) {
        return 0;
    }

    node_t *np;
    for (np = qp->front; np != NULL; np = np->next) {
        len += 1;
    }

    return len;
}

int32_t qput(queue_t *qp, void *elementp) {
    node_t *nodep = data_to_node(elementp);
    if (nodep == NULL) {
        return 1;
    }
    if (qp->front == NULL && qp->back == NULL) { /* empty queue */
        qp->front = nodep;
        qp->back = nodep;
    } else { /* non-empty queue */
        qp->back->next = nodep;
        qp->back = nodep;
    }
    return 0;
}

void *qget(queue_t *qp) {
    if (qp->front == NULL && qp->back == NULL) {
        return NULL;
    }
    void *tmp = qp->front->data;
    node_t *tmpnodep = qp->front;
    if (qp->front == qp->back) {
        qp->front = NULL;
        qp->back = NULL;
    } else {
        qp->front = qp->front->next;
    }
    free(tmpnodep);
    return tmp;
}

void qapply(queue_t *qp, void (*fn)(void *elementp)) {
    node_t *np;
    for (np = qp->front; np != NULL; np = np->next) {
        fn(np->data);
    }
}

void *qsearch(queue_t *qp, bool (*searchfn)(void *elementp, const void *keyp), const void *skeyp) {
    node_t *np;
    for (np = qp->front; np != NULL; np = np->next) {
        if (searchfn(np->data, skeyp)) {
            return np->data;
        }
    }
    return NULL;
}

void *qremove(queue_t *qp, bool (*searchfn)(void *elementp, const void *keyp), const void *skeyp) {
    node_t *np;
    node_t *nf;
    for (np = qp->front; np != NULL; np = np->next) {
        if (searchfn(np->data, skeyp)) {
            if (qp->front == qp->back) { /* only element */
                qp->front = NULL;
                qp->back = NULL;
            } else if (qp->back == np) { /* element at end */
                nf->next = NULL;
                qp->back = nf;
            } else if (qp->front == np) { /* element at front */
                qp->front = np->next;
            } else { /* element in middle */
                nf->next = np->next;
            }
            void *tmp = np->data;
            free(np);
            return tmp;
        }
        nf = np;
    }
    return NULL;
}

// cs58 addition
int qremove_all(queue_t *qp, bool (*searchfn)(void *elementp, const void *keyp), const void *skeyp) {
    node_t *np;
    node_t *nf;

    for (np = qp->front; np != NULL; np = np->next) {
        if (searchfn(np->data, skeyp)) {
            if (qp->front == qp->back) { /* only element */
                qp->front = NULL;
                qp->back = NULL;
            } else if (qp->back == np) { /* element at end */
                nf->next = NULL;
                qp->back = nf;
            } else if (qp->front == np) { /* element at front */
                qp->front = np->next;
            } else { /* element in middle */
                nf->next = np->next;
            }
            // save old np's attributes
            void *tmp = np->data;
            node_t *tmp2 = np->next;
            free(np);
            // restore attributes
            np->data = tmp;
            np->next = tmp2;
        } else {
            nf = np;
        }
    }
    return 0;
}

void qconcat(queue_t *q1p, queue_t *q2p) {
    int first_empty = q1p->front == NULL && q1p->back == NULL;
    int second_empty = q2p->front == NULL && q2p->back == NULL;

    if (first_empty && second_empty) { /* both empty */
        ;
    } else if (first_empty) { /* first empty */
        q1p->front = q2p->front;
        q1p->back = q2p->back;
    } else if (second_empty) { /* second empty */
        ;
    } else { /* both full */
        q1p->back->next = q2p->front;
        q1p->back = q2p->back;
    }
    free(q2p);
}
