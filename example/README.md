Example Program
===============
This is a horribly contrived example program which demonstrates how to use
`packetchecksum_calculate` as well as provides some lightweight testing.

Each packet will be written to stdout in hex before it is sent.

I compile and run it with the following:
```ksh
cc -Wall --pedantic -fPIC -o libpacketchecksum.so *.c -shared && \
(cd example/ && \
cc -O2 -Wall --pedantic -L.. -I.. example.c -lpcap -lpacketchecksum && \
doas sh -c 'LD_LIBRARY_PATH=.. ./a.out em0'
echo $?)
```
You'll almost certainly have to change parts of that.
