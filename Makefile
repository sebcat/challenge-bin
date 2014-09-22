
# This is not intended to be portable

CC=clang
RM=rm -f

all:
	$(CC) -o f fnv1a_file.c
	gzip -9c solution > packed_solution 
	./f '20sec-t14' packed_solution > encoded_solution
	nasm -fbin -osect2014 sect2014.asm
	chmod u+x ./sect2014 

clean:
	$(RM) sect2014 f packed_solution encoded_solution 
