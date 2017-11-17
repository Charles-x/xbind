#!/bin/sh
chown -R named:named /var/cache/bind
chmod -R root:named /etc/bind
/usr/bin/python /usr/bin/supervisord
