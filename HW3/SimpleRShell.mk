#SimpleRShell.mk
# to use it, do: make -f SimpleRShell.mk


CC=gcc

all: SimpleRShellClient SimpleRShellServer

SimpleRShellClient: SimpleRShellClient.o
	$(CC) -lcrypto -w -o SimpleRShellClient SimpleRShellClient.o

SimpleRShellClient.o: SimpleRShellClient.c
	$(CC) -c -std=gnu89 -w SimpleRShellClient.c

SimpleRShellServer: SimpleRShellServer.o
	$(CC) -lcrypto -w -o SimpleRShellServer SimpleRShellServer.o

SimpleRShellServer.o: SimpleRShellServer.c 
	$(CC) -c -std=gnu89 -w SimpleRShellServer.c




