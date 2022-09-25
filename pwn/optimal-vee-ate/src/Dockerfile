FROM ghcr.io/downunderctf/docker-vendor/nsjail:ubuntu-21.04

ENV JAIL_CWD=/chal
COPY ./nsjail.cfg /home/ctf/

COPY ./flag.txt /home/ctf/chal/
COPY ./d8 /home/ctf/chal/
COPY ./snapshot_blob.bin /home/ctf/chal/
COPY ./worker.js /home/ctf/chal/
COPY ./challenge.sh /home/ctf/chal/pwn

RUN mv /home/ctf/chal/flag.txt /home/ctf/chal/$(tr -dc a-z0-9 </dev/urandom | head -c 32)_flag.txt
