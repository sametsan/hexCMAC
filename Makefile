
TARGET=hexCMAC

FILES=main.c 

FLAGS= -lcrypto


all:
	$(CC) $(FILES) $(FLAGS) -o $(TARGET)