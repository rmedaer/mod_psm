
all: build

build: mod_psm.la
	sudo apxs -i -a -n psm mod_psm.la
	sudo service apache2 restart

mod_psm.la: mod_psm.c mod_psm_utils.c mod_psm_cookies.c mod_psm_driver_redis.c *.h
	apxs -DPSM_DEBUG=1 -lhiredis -ljansson -c mod_psm.c mod_psm_utils.c mod_psm_cookies.c mod_psm_driver_redis.c
