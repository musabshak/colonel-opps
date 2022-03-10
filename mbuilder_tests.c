/**
 * mbuilder_tests.c
 *
 * Tests the functionality of the malloc builder. Note that while the malloc builder
 * is written to be used by Yalnix, these tests are not meant to be run on Yalnix,
 * but rather in the standard Thayer environment, with the standard C library. The
 * reason for this is so we can use tools such as `valgrind`.
 */

#include "mbuilder.h"

int test1_unwind() { m_builder_t *mbuilder = m_builder_init(); }

int main() {}
