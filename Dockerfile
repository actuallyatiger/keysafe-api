FROM python:3.11-alpine

WORKDIR /app

ENV PYTHONUNBUFFERED True

COPY requirements.txt ./
RUN pip3 install --no-cache-dir -r requirements.txt

COPY . .

EXPOSE 5000
ENV PORT 5000

CMD cd api; exec gunicorn --bind :$PORT --workers 2 --threads 4 app:app
