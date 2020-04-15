FROM ubuntu:18.04

ENV USER likkrid

# setup user
RUN useradd $USER

# setup python
RUN apt-get update
RUN apt-get install -y python python-pip
RUN pip install pycrypto

# setup home files
COPY src /home/$USER/$USER

# making the owner root prevents users from using chmod on the directory and its files
RUN chown -R root:$USER /home/$USER

# root and $USER can access and list files in the directory, but cannot create or delete files
RUN chmod -R 550 /home/$USER

# make the python file executable,
RUN chmod +x /home/$USER/$USER/rabin.py

EXPOSE 6776
WORKDIR /home/$USER
CMD ["likkrid/rabin.py"]
