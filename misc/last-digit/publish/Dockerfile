FROM python:3.10.7

RUN /usr/sbin/useradd --no-create-home -u 1000 ctf

COPY flag.txt /
COPY last-digit.py /home/ctf/

RUN chmod a+x /home/ctf/last-digit.py

RUN apt-get update && apt-get install -y socat && rm -rf /var/lib/apt/lists/*

USER ctf

CMD socat \
		TCP-LISTEN:1337,reuseaddr,fork \
		EXEC:"python -u /home/ctf/last-digit.py"
