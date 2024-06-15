CC = gcc
CFLAGS = -Wall
LIBS = -lnetfilter_queue 
IP_ADDRESS = 

TARGET = ttload

all: $(TARGET)

$(TARGET): main.c
	$(CC) $(CFLAGS) -o $@ $< $(LIBS)

run: $(TARGET)
	sudo ./$(TARGET) -f ./testfile -i $(IP_ADDRESS)

clean:
	rm -f $(TARGET)

.PHONY: all run clean
