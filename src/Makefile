PROG=ft_bt_remote_server
OBJS=gatt-server.o att.o queue.o util.o gatt-db.o mainloop.o timeout-mainloop.o io-mainloop.o uuid.o crypto.o 
LIB=gatt

all: $(PROG)

install: $(PROG)
	install $(PROG) /usr/bin

$(PROG): $(PROG).o lib$(LIB).a
	$(CC) -s -o $@ $(PROG).o -L. -l$(LIB) -lbluetooth

lib$(LIB).a: $(OBJS)
	$(AR) rcs $@ $(OBJS)

.c.o:
	$(CC) -I. -I./lib -I./src/shared -o $@ -c $<

clean::
	rm -f *.o *~ $(PROG)
