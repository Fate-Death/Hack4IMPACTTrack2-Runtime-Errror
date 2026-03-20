CC = gcc
CFLAGS = -Wall -Wextra -O2

TARGET = pattern_detect

all: $(TARGET)

$(TARGET): pattern_detect.c
	$(CC) $(CFLAGS) -o $(TARGET) pattern_detect.c

clean:
	rm -f $(TARGET)

test: $(TARGET)
	@echo "--- Testing SQL Injection ---"
	@echo "' OR 1=1 --" | ./$(TARGET)
	@echo ""
	@echo "--- Testing XSS ---"
	@echo "<script>alert('XSS')</script>" | ./$(TARGET)
	@echo ""
	@echo "--- Testing Safe Input ---"
	@echo "Hello World" | ./$(TARGET)

.PHONY: all clean test
