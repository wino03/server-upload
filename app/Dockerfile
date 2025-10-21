FROM python:3.11-slim
 
WORKDIR /app
 
COPY app.py /app
COPY ssl /app/ssl
 
RUN pip install flask bcrypt
 
VOLUME ["/uploads"]
 
EXPOSE 5000
 
CMD ["python", "app.py"]