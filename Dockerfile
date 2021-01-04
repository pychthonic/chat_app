FROM ubuntu

RUN apt-get update -y && apt-get install -y bash build-essential python3-pip python3-dev libffi-dev

WORKDIR /app

COPY . ./

RUN pip3 install .

RUN chmod u+x ./run.sh

ENTRYPOINT ./run.sh