FROM python:3.11-slim
 
WORKDIR /app
 
COPY app.py /app
 
RUN pip install flask bcrypt
 
VOLUME ["/uploads"]
 
EXPOSE 5000
 
CMD ["python", "app.py"]