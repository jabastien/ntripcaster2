FROM ubuntu:18.04

ENV ver=2.0

RUN apt-get update && apt-get install -y build-essential\
    wget\
    gcc\
    git

ARG NTRIPCASTER_URL=https://github.com/rinex20/ntripcaster2.git
RUN git clone --depth 1 ${NTRIPCASTER_URL}

EXPOSE 2101 8001 8002
CMD ["bash"]



