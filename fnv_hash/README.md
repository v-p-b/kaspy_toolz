FNV hash
========

Standalone implementation of the [FNV checksum](https://en.wikipedia.org/wiki/Fowler%E2%80%93Noll%E2%80%93Vo_hash_function) as implemented by various Kaspersky products, based on [ripr](https://github.com/pbiernat/ripr).

Setup
-----

I don't want to publish copyrighted code so you have to carve out relevant machine code from Kaspersky's `prremote.dll` yourself. I used `ripr` and Binary Ninja to generate the original code, but feel free to use your favorite disassebmler to find and grab the relevant pieces. 

There are four functions involved: `hash`, `loop`, `multi`, and `calc`. These are represented by four class members of the `FNV_hash` Python class. 

To find the code for `hash` look for functions that move the two DWORD parts of the FNV offset basis into two registers:

```asm
MOV ECX,0x84222325
MOV EDX,0xcbf29ce4
```

This should yield two candidates: you should use the one that returns `0x8000005a` at the end of the function.

The code for `calc` is the first function referenced by `hash`.

The code for `loop` is the only function referenced by `calc`.

The code for `multi` is the only function referenced by `loop`, also known as `allmul()`.

Support
-------

Expect none.
