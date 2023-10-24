from ubuntu:22.04

ARG SCION_UID=1000
ARG SCION_GID=1000

RUN apt-get update && apt-get upgrade -y
RUN apt-get install -y supervisor python3-pip iproute2 iputils-ping iptables
RUN pip3 install supervisor-wildcards appdeps

# Create scion user
RUN groupadd -g ${SCION_GID:?} scion
RUN useradd -m -s /bin/bash -u ${SCION_UID:?} -g scion -G sudo scion

# Create dispatcher and sciond directories with correct owner
RUN mkdir -p /run/shm/dispatcher
RUN chown scion:scion /run/shm/dispatcher
RUN mkdir -p /run/shm/sciond
RUN chown scion:scion /run/shm/sciond

# Supervisord configuration
COPY supervisord.conf /home/scion/scion/supervisor/
COPY entrypoint.sh /home/scion/scion/supervisor/

USER scion
WORKDIR /home/scion/scion
RUN echo 'PATH=$PATH:$HOME/scion/bin:$HOME/scion-apps/bin' >> ~/.profile && . ~/.profile

CMD ["supervisord", "-c", "supervisor/supervisord.conf"]
