default: build

build:
	nasm -f elf64 ./main.asm && ld ./main.o
	strace ./a.out

debug: 
	nasm -f elf64 ./main.asm && ld ./main.o
	strace ./a.out