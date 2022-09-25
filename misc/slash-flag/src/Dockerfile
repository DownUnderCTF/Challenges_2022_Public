FROM ghcr.io/downunderctf/docker-vendor/nsjail:debian-10 AS nsjail

FROM node:16.17.0

COPY --from=nsjail /docker-init /docker-init
COPY --from=nsjail /usr/bin/nsjail /usr/bin/
RUN useradd -r -m ctf

ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
    libprotobuf17 libnl-route-3-200 sudo && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /usr/src/app

COPY challenge/package*.json ./

RUN npm install

COPY ./challenge .

RUN mkdir /mounts && \
    mkdir /storage && \
    mkdir /flag && \
    mv ./flag.txt /flag/ && \
    echo "nobody ALL=(root) NOPASSWD: /usr/src/app/run_lock" >> /etc/sudoers

ENTRYPOINT ["/docker-init/docker-entrypoint.sh"]
CMD ["sudo", "-E", "-u", "nobody", "node", "index.js" ]
