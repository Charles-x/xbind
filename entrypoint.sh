#!/bin/sh
chown -R named:named /var/cache/bind
chown -R named:named /etc/bind
/usr/bin/python /usr/bin/supervisord
