FROM python:3.11-slim
 
WORKDIR /app
 
COPY app.py /app
 
RUN pip install flask bcrypt
 
VOLUME ["/app/provisioning"]
 
EXPOSE 5000
 
CMD ["python", "app.py"]