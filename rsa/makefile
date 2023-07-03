CC = gcc
OPT = -O3
#OPT = -g
WARN = -Wall

CFLAGS = $(OPT) $(WARN) $(INC) $(LIB)

# List all your .cc/.cpp files
SIM_SRC = rsa_encrypt.c

SIM_OBJ = rsa_encrypt.o

#################################
all: $(SIM_OBJ)
	$(CC) -o rsa_encrypt $(CFLAGS) $(SIM_OBJ) -lm
	@echo "----------done-----------"

.c.o:
	$(CC) $(CFLAGS) -c $*.c

clean:
	rm -f *.o ti
clobber:
	rm -f *.o
