# Checkpoint 5 submission

The submission branch is `checkpoint-5`. To build, run `make all`.

## Testing
Tests relating to terminal I/O live in `tests/terminal_tests.c`. Some examples of things we
tested were:
- regular read/write from terminal, of length less than the max line length of the terminal
- writing for then the max line length to a terminal
- multiple processes trying to write more than max line length to the same terminal

All tests presently behave as expected.
