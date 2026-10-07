CC ?= gcc
LD ?= ld
CFLAGS = -I$(OSSL)/include -fPIC
LDFLAGS = -L$(OSSL) -shared -fPIC -Wl,--version-script=./sss.ld

.PHONY: clean

all: sss.so

clean:
	rm -f *.o *.so

sss.so: prov.o keymgmt.o
	$(CC) $(LDFLAGS) -o $@ $^

%.o: %.c
	$(CC) $(CFLAGS) -fPIC -c $< -o $@
