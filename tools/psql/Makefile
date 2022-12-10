
CFLAGS += -I/home/ewust/postgresql-9.5.10/src/include/
#bump this for each new make install, or psql will crash and delete your data...
VERSION=1.1

pfunc.so: pfunc.c
	$(CC) $(CFLAGS) -fpic -O3 -c $^
	$(CC) -shared -o $@ pfunc.o

install: pfunc.so
	cp pfunc.so /var/lib/postgresql/pfunc-v$(VERSION).so
	#~postgres/

clean:
	rm pfunc.so
