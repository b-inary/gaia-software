
TARGET = sim

CFLAGS = -Wall -Wextra -O2 -std=c99 -pedantic
LDLIBS = -lm

$(TARGET):

PHONY: clean
clean:
	rm -f $(TARGET) *.out *.out.s

