all: libkeccak.a

libkeccak.a: KeccakSponge.o KeccakF-1600-opt64.o KeccakNISTInterface.o
	ar -rs $@ $<

clean:
	rm -f *.a *.o
