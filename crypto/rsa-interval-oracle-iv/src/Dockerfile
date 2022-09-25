FROM ghcr.io/downunderctf/docker-vendor/nsjail:ubuntu-22.04

RUN pip install -t /lib/python3/dist-packages pycryptodome
env TIME_LIMIT=180

COPY ./flag.txt /home/ctf/chal/flag.txt
COPY ./rsa-interval-oracle-iv.py /home/ctf/chal/pwn
