FROM python:3.9-slim-bullseye

COPY ./getfinalflag_src/getfinalflag.c /tmp/getfinalflag.c

RUN apt update && \
        apt install -y default-jdk libmagic1 build-essential && \
        mkdir -p /opt/api && mkdir -p /etc/assapi/ && \
        openssl genrsa -out /etc/assapi/private.pem 4096 && \
        openssl rsa -in /etc/assapi/private.pem -pubout -outform PEM -out /etc/assapi/public.pem && \
        chmod 644 /etc/assapi/private.pem && chmod 644 /etc/assapi/public.pem && \
        gcc -o /usr/bin/getfinalflag /tmp/getfinalflag.c && \
        rm /tmp/getfinalflag.c && \
        apt remove --purge -y build-essential && \
        rm -rf /var/lib/apt/lists/*

COPY ass/requirements.txt /opt/ass/requirements.txt
RUN pip3 install -r /opt/ass/requirements.txt

COPY ass/ /opt/ass
RUN chmod +x /opt/ass/start-ass.sh

RUN useradd -m ghostccamm
COPY ./getfinalflag_src/flag.txt /home/ghostccamm/flag.txt

RUN chmod -R 770 /home/ghostccamm && \
        chown ghostccamm:ghostccamm /usr/bin/getfinalflag && \
        chmod u+s /usr/bin/getfinalflag && \
        chown ghostccamm:ghostccamm /home/ghostccamm/flag.txt && \
        chmod 440 /home/ghostccamm/flag.txt

RUN useradd -m ductf-chal

USER ductf-chal
WORKDIR /opt/ass
CMD ["/opt/ass/start-ass.sh"]