
all: build

build: mod_cookies_encapsulation.la
	sudo apxs -i -a -n mod_cookies_encapsulation mod_cookies_encapsulation.la
	sudo service apache2 restart

mod_cookies_encapsulation.la: mod_cookies_encapsulation.c
	apxs -c mod_cookies_encapsulation.c
