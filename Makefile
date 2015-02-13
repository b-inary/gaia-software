
TARGET = sim

CFLAGS = -Wall -Wextra -O2 -std=gnu99 -g
LDLIBS = -lm

$(TARGET):

PHONY: clean
clean:
	rm -f $(TARGET) *.out *.out.s

