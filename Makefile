
TARGET = sim

CFLAGS = -Wall -Wextra -O2 -std=c99 -pedantic
LDFLAGS = -Wl,--no-as-needed -lm

$(TARGET):

PHONY: clean
clean:
	rm -f $(TARGET)

