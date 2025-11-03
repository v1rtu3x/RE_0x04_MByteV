# Makefile
CC := gcc
CFLAGS := -O2 -pipe -s
SRC := src/mbytev.c
TARGET := mbytev
BUILD_DIR := build

all: $(BUILD_DIR)/$(TARGET)

$(BUILD_DIR)/$(TARGET): $(SRC)
	@mkdir -p $(BUILD_DIR)
	$(CC) $(CFLAGS) -o $@ $(SRC)

release: all
	@mkdir -p $(BUILD_DIR)/release
	strip $(BUILD_DIR)/$(TARGET) || true
	cp $(BUILD_DIR)/$(TARGET) $(BUILD_DIR)/release/$(TARGET)

clean:
	-rm -rf $(BUILD_DIR)