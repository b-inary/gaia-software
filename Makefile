
TARGET = sim
SRCS = sim.c

CFLAGS = -Wall -Wextra -O2 -std=c99

$(TARGET): $(SRCS)
	$(CC) $(CFLAGS) -o $@ $^ -lm

PHONY: clean
clean:
	rm -f $(TARGET)

