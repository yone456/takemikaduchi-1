FROM ubuntu:20.04

LABEL maintainer="rnakata@iisec/hitotsubashi"
LABEL version="0.1"
LABEL description="Redchef - takemikaduchi"

SHELL ["/bin/bash", "-c"]

RUN apt-get update
RUN apt-get install -y language-pack-ja-base language-pack-ja locales
RUN locale-gen ja_JP.UTF-8
RUN echo "export LANG=ja_JP.UTF-8" >> ~/.bashrc
RUN source ~/.bashrc
RUN apt-get install -y software-properties-common
RUN add-apt-repository ppa:deadsnakes/ppa
RUN apt-get install -y python3.7 python3.7-dev python3.7-venv
RUN update-alternatives --install /usr/bin/python3 python3 /usr/bin/python3.8 100
RUN update-alternatives --install /usr/bin/python3 python3 /usr/bin/python3.7 110
RUN echo "1" | update-alternatives --config python3
RUN apt-get install -y python3-pip
RUN apt-get install -y nmap

COPY Redchef/ /tmp/Redchef/

RUN pip3 install -r /tmp/Redchef/requirements.txt 
RUN pip3 install torch 

RUN export CUDA_VISIBLE_DEVICES='0'


