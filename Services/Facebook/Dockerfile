FROM ubuntu:17.10

RUN apt-get update -y
RUN apt-get install -y python3-pip python3-dev build-essential git

COPY . /Facebook
WORKDIR /Facebook

RUN pip3 install -e git+https://github.com/mobolic/facebook-sdk.git#egg=facebook-sdk
RUN pip3 install -r requirements.txt
ENTRYPOINT ["python3"]
CMD ["facebookService.py"]
