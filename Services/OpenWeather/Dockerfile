FROM ubuntu:17.10

RUN apt-get update -y
RUN apt-get install -y python3-pip python3-dev build-essential

COPY . /OpenWeather
WORKDIR /OpenWeather

RUN pip3 install -r requirements.txt
ENTRYPOINT ["python3"]
CMD ["Opw.py"]
