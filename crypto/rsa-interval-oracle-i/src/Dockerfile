FROM ghcr.io/downunderctf/docker-vendor/nsjail:ubuntu-22.04

RUN pip install -t /lib/python3/dist-packages pycryptodome
env TIME_LIMIT=1200

COPY ./flag.txt /home/ctf/chal/flag.txt
COPY ./rsa-interval-oracle-i.py /home/ctf/chal/pwn
