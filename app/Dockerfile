FROM python:3.11-slim
 
WORKDIR /app
 
COPY app.py /app
COPY ssl /app/ssl
 
RUN pip install flask bcrypt gunicorn
 
VOLUME ["/uploads"]
 
EXPOSE 5000
 
CMD ["gunicorn", "--certfile=/app/ssl/server.crt", "--keyfile=/app/ssl/server.key", "-b", "0.0.0.0:5000", "app:app", "--workers=2", "--access-logfile", "-"]