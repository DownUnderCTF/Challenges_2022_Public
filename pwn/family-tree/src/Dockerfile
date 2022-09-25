FROM ghcr.io/downunderctf/docker-vendor/nsjail:ubuntu-18.04

ENV JAIL_CWD=/chal
COPY ./libc-2.27.so /lib/x86_64-linux-gnu/libc.so.6
COPY ./flag.txt /home/ctf/chal/flag.txt
COPY ./family_tree /home/ctf/chal/pwn
