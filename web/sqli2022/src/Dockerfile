FROM python:3.10

WORKDIR /app
COPY app.py .

RUN pip3 install flask

ARG FLAG
ENV FLAG=DUCTF{alternative_solution_was_just_to_crack_the_hash_:p}

CMD ["python3", "-m", "flask", "run", "--host=0.0.0.0", "--port=1337"]
