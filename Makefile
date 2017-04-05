CC=gcc
CFLAGS=-c -Wall
PARTS=sniffer.o main.o

# Directorios
OBJ=obj
SRC=src
INC=include

# Bibliotecas externas
LIBS=pcap

all: build

build: $(PARTS)
	@echo "Enlazando"
	@$(CC) $(OBJ)/*.o -o bin/sniffer $(patsubst %,-l%,$(LIBS))
	@echo -e "\nListo. El programa se encuentra en el directorio bin/"

%.o: $(SRC)/%.c
	@echo "Compilando $(<)"
	@if [ ! -d "$(OBJ)" ]; then mkdir $(OBJ); fi
	@$(CC) $(CFLAGS) $< -o $(OBJ)/$@ -I $(INC)

clean:
	@rm -vf bin/* obj/*.o
