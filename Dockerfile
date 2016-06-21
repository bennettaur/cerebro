FROM python:2.7.10

MAINTAINER bennettaur

RUN apt-get update && apt-get upgrade -y

RUN apt-get install -y \
	build-essential \
	python-dev \
	curl \
	libcurl4-openssl-dev \
	tcpdump \
	libpcap-dev \
	git

RUN mkdir /cerebro

WORKDIR /cerebro

# Download libdnet & pylibpcap
RUN wget https://libdnet.googlecode.com/files/libdnet-1.12.tgz && \
tar zxf libdnet-1.12.tgz && \
wget http://sourceforge.net/projects/pylibpcap/files/pylibpcap/0.6.4/pylibpcap-0.6.4.tar.gz && \
tar zxf pylibpcap-0.6.4.tar.gz

# Install libdnet
WORKDIR /cerebro/libdnet-1.12
RUN ./configure && make && make install
WORKDIR /cerebro/libdnet-1.12/python
RUN python ./setup.py build && python ./setup.py install

#Install pylibpcap
WORKDIR /cerebro/pylibpcap-0.6.4
RUN python setup.py build && python setup.py install

RUN mkdir -p /var/log/cerebro

ENTRYPOINT ["python"]

ENV PYTHONPATH=/cerebro

CMD ["cerebro.py"]

WORKDIR /cerebro
COPY ./dependencies /cerebro/

RUN pip install -r dependencies && pip install ipython

COPY . /cerebro