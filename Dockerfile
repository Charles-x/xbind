FROM alpine:latest
EXPOSE 53 53/udp

RUN apk --update add bind python py-pip supervisor
RUN pip install flask dnspython
COPY supervisor/supervisord.conf /etc/supervisord.conf
COPY xbind /xbind
RUN mkdir -m 0755 -p /var/run/named && chown -R root:named /var/run/named

# /var/cache/bind needs to be owned by "bind"
# since we are mounting, do it manually
# NOTE: Per Dockerfile manual --> need to mkdir the mounted dir to chown
RUN mkdir -m 0755 -p /var/cache/bind && touch /var/cache/bind/docker-init && chown -R named:named /var/cache/bind

# Mounts
# NOTE: Per Dockerfile manual -->
#	"if any build steps change the data within the volume
# 	 after it has been declared, those changes will be discarded."
VOLUME ["/etc/bind"]
VOLUME ["/var/cache/bind"]

COPY entrypoint.sh /
ENTRYPOINT ["/entrypoint.sh"]
