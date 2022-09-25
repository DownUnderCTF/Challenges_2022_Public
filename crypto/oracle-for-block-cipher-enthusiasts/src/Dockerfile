FROM ghcr.io/downunderctf/docker-vendor/nsjail:ubuntu-22.04

RUN pip install -t /lib/python3/dist-packages pycryptodome

COPY ./flag.txt /home/ctf/chal
COPY ./ofb.py /home/ctf/chal/pwn
