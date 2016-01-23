
all: build

build: mod_example.la
	sudo apxs -i -a -n mod_example mod_example.la
	sudo service apache2 restart

mod_example.la: mod_example.c
	apxs -c mod_example.c
