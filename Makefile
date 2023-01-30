# Makefile for file ipk-sniffer.c
# Ivan Golikov (xgolik00)

CC=gcc
CFLAGS=-c -Wall -D_GNU_SOURCE
LDFLAGS=-lpcap

.PHONY: all ipk-sniffer.c ipk-sniffer

all: ipk-sniffer.c ipk-sniffer

ipk-sniffer: ipk-sniffer.o 
	$(CC) $^ -o $@ $(LDFLAGS)

.c.o:
	$(CC) $(CFLAGS) -I. $< -o $@

clean:
	rm -rf ipk-sniffer.o ipk-sniffer