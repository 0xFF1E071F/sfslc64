APP=sfslc

all: $(APP) clean

$(APP): $(APP).o
	gcc -s -o $(APP) $(APP).o 

$(APP).o: $(APP).asm
	nasm -f elf64 $(APP).asm

clean:
	rm $(APP).o
