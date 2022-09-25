FROM ghcr.io/downunderctf/docker-vendor/nsjail:ubuntu-22.04

RUN pip install -t /lib/python3/dist-packages pycryptodome Pillow

COPY ./nsjail.cfg /home/ctf
COPY ./flag.txt /home/ctf/chal
COPY ./file-magic.py /home/ctf/chal/pwn
