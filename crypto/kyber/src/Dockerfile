FROM ghcr.io/downunderctf/docker-vendor/nsjail:ubuntu-22.04

ENV TIME_LIMIT=2700
ENV JAIL_CWD=/chal

COPY ./libpqcrystals_kyber512_ref.so /home/ctf/chal
COPY ./flag.txt /home/ctf/chal
COPY ./kyber.py /home/ctf/chal/pwn
