#!/bin/sh
chown -R named:named /var/cache/bind
/usr/bin/python /usr/bin/supervisord
