# An access point as the tool sees it over SSH: dropbear (what UniFi APs run), an OpenSSH server as the
# second common server, busybox, and stubs for `iw` and `ifconfig` that answer from canned data and a
# small state directory. Nothing here is a real radio.
FROM alpine:3.22@sha256:5291449c3df73caf6ed85e649dec1b9e818b39a5d8c871e97afc13e9cd5e8fa8

RUN apk add --no-cache dropbear openssh-server openssh-keygen netcat-openbsd \
  && adduser -D -s /bin/sh scanuser \
  && echo "scanuser:scan-pass" | chpasswd \
  && mkdir -p /run/ifstate /run/stub /home/scanuser/.ssh /etc/dropbear \
  && chmod 1777 /run/ifstate /run/stub \
  && printf 'board.name=U6-Lite-Harness\n' >/etc/board.info \
  && ssh-keygen -A \
  && sed -i 's/^#\?PasswordAuthentication .*/PasswordAuthentication yes/; s/^#\?KbdInteractiveAuthentication .*/KbdInteractiveAuthentication yes/; s/^#\?PubkeyAuthentication .*/PubkeyAuthentication yes/' /etc/ssh/sshd_config \
  && printf 'Port 2222\nPermitRootLogin no\nAllowUsers scanuser\n' >>/etc/ssh/sshd_config

# The stubs shadow busybox's own applets whatever PATH a session gets: `/sbin/ifconfig` is a symlink into
# busybox (a plain COPY onto it would overwrite busybox itself), so the link goes first and the stubs are
# installed under every bin directory dropbear or sshd might put on PATH.
RUN rm -f /sbin/ifconfig
COPY stubs/iw /usr/bin/iw
COPY stubs/ifconfig /sbin/ifconfig
COPY entrypoint.sh /entrypoint.sh
RUN chmod 755 /usr/bin/iw /sbin/ifconfig /entrypoint.sh \
  && cp /usr/bin/iw /bin/iw && cp /sbin/ifconfig /bin/ifconfig && cp /sbin/ifconfig /usr/bin/ifconfig \
  && mkdir -p /opt/notimeout/bin \
  && for applet in $(busybox --list); do [ "$applet" = timeout ] || ln -s /bin/busybox "/opt/notimeout/bin/$applet"; done \
  && ln -sf /usr/bin/iw /opt/notimeout/bin/iw && ln -sf /sbin/ifconfig /opt/notimeout/bin/ifconfig \
  && cp -r /opt/notimeout /opt/oldtimeout \
  && printf '#!/bin/sh\n# busybox before 1.30: `timeout -t SECS PROG`; the plain `timeout SECS PROG` form is an error.\ncase "$1" in -t) shift 2; exec "$@" ;; *) echo "timeout: invalid number" >&2; exit 1 ;; esac\n' >/opt/oldtimeout/bin/timeout \
  && chmod 755 /opt/oldtimeout/bin/timeout

EXPOSE 22 2222
ENTRYPOINT ["/entrypoint.sh"]
