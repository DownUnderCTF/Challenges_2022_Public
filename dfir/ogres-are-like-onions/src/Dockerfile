FROM python:alpine

WORKDIR /app
COPY . /app

# oops that meme is only for me
RUN rm memes/flag.jpg

EXPOSE 8000

CMD [ "/usr/local/bin/python", "-m", "http.server" ]
