# Makefile

all:
	$(MAKE) -C src

install:
	$(MAKE) -C src install
	install ft_bt_remote_start.sh /usr/bin

clean:
	$(MAKE) -C src clean
	rm -f *~ 
