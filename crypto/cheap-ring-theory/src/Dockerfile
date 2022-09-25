FROM sagemath/sagemath:9.1

ENV DEBIAN_FRONTEND=noninteractive
RUN sudo apt-get update \
    && sudo apt-get install -y socat --fix-missing \
    && sudo rm -r /var/lib/apt/lists/*

COPY ./crt.sage /home/ctf/chal/chal.sage
COPY ./flag.txt /home/ctf/chal/
WORKDIR /home/ctf/chal
ENTRYPOINT sudo socat -dd TCP4-LISTEN:1337,fork,reuseaddr EXEC:"sage chal.sage"
