CC = gcc
CFLAGS =
# CFLAGS = -g

# Solaris LIBS
# LIBS = -lresolv -lsocket -lnsl
# Linux LIBS
LIBS = -lcrypto

INCLUDES =
OBJS = telnetenable.o blowfish.o md5.o
SRCS = telnetenable.c blowfish.c md5.c

telnetenable: ${OBJS}
	${CC} ${CFLAGS} ${INCLUDES} -o $@ ${OBJS} ${LIBS}

.c.o:
	${CC} ${CFLAGS} ${INCLUDES} -c $<

clean:
	rm *.o
