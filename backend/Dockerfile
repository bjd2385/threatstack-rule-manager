FROM python:3.8.7

RUN mkdir /app
WORKDIR /app
ADD . .
RUN pip install --upgrade pip && pip install --no-cache-dir -r requirements.txt && python setup.py install
EXPOSE 8000

ENTRYPOINT ["bash", "app.sh"]
