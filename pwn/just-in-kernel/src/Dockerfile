FROM ubuntu:20.04

ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update \
    && apt-get install -y socat qemu-system-x86 --fix-missing \
    && rm -r /var/lib/apt/lists/*

RUN mkdir /home/ctf
WORKDIR /home/ctf

COPY ./bzImage /home/ctf
COPY ./initramfs.cpio.gz /home/ctf
COPY ./launch.sh /home/ctf

ENTRYPOINT socat -dd TCP4-LISTEN:1337,fork,reuseaddr EXEC:"timeout 600 ./launch.sh"
