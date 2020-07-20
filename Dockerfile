FROM python:3.8.4-buster

RUN apt update
RUN apt install -y python3-pip

RUN pip3 install fabric

CMD [ "python3", "/root/deploy.py" ]

