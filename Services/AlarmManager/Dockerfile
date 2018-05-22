FROM ubuntu:17.10

RUN apt-get update -y
RUN apt-get install -y python3-pip python3-dev build-essential
#RUN echo "LC_ALL=en_US.UTF-8" >> /etc/environment
#RUN echo "en_US.UTF-8 UTF-8" >> /etc/locale.gen
#RUN echo "LANG=en_US.UTF-8" > /etc/locale.conf
#RUN locale-gen en_US.UTF-8
COPY . /AlarmManager
WORKDIR /AlarmManager

RUN pip3 install -r requirements.txt
ENTRYPOINT ["python3"]
CMD ["alarmManager.py"]