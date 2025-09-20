# SHA

C implementations of the SHA-1 and SHA-2 families of hash functions.

## Building

You will need `CMake` and a C compiler.

```sh
cmake -S . -B build
cmake --build build --target test_all
```

## Running

```sh
$ echo -n "abc" | build/sha 256 24
ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad
```
