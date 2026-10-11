# The oldest OpenSSH client the tool supports. Debian bullseye ships openssh-client 8.4p1, the release that
# introduced SSH_ASKPASS_REQUIRE; the floor tests run the tool's exact argv from inside this container.
FROM debian:bullseye-slim@sha256:e5b6442dd2e9684cf5e87d8338b5968f3b348636fc0be6d7850a381e3731a2bd

# bullseye left the regular mirrors in 2026; archive.debian.org keeps every published package.
RUN printf 'deb http://archive.debian.org/debian bullseye main\ndeb http://archive.debian.org/debian-security bullseye-security main\n' >/etc/apt/sources.list \
  && rm -f /etc/apt/sources.list.d/*.sources \
  && apt-get -o Acquire::Check-Valid-Until=false update \
  && apt-get install -y --no-install-recommends openssh-client \
  && rm -rf /var/lib/apt/lists/* \
  && ssh -V 2>&1 | grep -q 'OpenSSH_8.4' \
  && useradd -m -s /bin/sh tester \
  && printf '#!/bin/sh\nprintf "%%s\\n" "$UWO_SSH_PASSWORD"\n' >/usr/local/bin/askpass \
  && chmod 755 /usr/local/bin/askpass

USER tester
WORKDIR /home/tester
