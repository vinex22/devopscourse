FROM python:3.8-slim-buster
ADD hardening_script_16_august_2022.sh /
#RUN export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
#RUN chmod +777 hardening_script_16_august_2022.sh
USER root
RUN  su -c  ./hardening_script_16_august_2022.sh
WORKDIR /app

COPY requirements.txt requirements.txt
RUN pip3 install -r requirements.txt

COPY . .

CMD [ "python3", "-m" , "flask", "run", "--host=0.0.0.0"]