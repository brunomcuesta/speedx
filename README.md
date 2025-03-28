# SpeedX

![speedx](https://i.imgur.com/SU29WSn.png)

SpeedX is a python script for bypassing blocked hosts (status 403) using HTTP headers and IPs combinations.

To speed up the bypass process, SpeedX uses threading. Testing is done using each header and ip combination for each domain. This reduces the number of requests in each domain.

## Installation

### With pipx (recommended)

```
$ git clone https://github.com/brunomcuesta/speedx.git
$ cd speedx
$ pipx install .
```

- Running

```
$ speedx -h                                                                           
usage: speedx [-h] -i IPS -d DOMAINS [-o OUTPUT]

403 bypass test using HTTP headers and IPs

options:
  -h, --help            show this help message and exit
  -i IPS, --ips IPS     File containing list of IPs
  -d DOMAINS, --domains DOMAINS
                        File containing list of domains
  -o OUTPUT, --output OUTPUT
                        File to save the bypass results (optional)
  -t, --threads THREADS
                        Number of threads to use (default is 5)
```

### With venv

```
$ git clone https://github.com/brunomcuesta/speedx.git
$ cd speedx
$ python3 -m venv .env
$ source .env/bin/activate
$ pip install -r requirements.txt
```

- Running

```
$ python3 speedx.py -h                                                                           
usage: speedx.py [-h] -i IPS -d DOMAINS [-o OUTPUT]

403 bypass test using HTTP headers and IPs

options:
  -h, --help            show this help message and exit
  -i IPS, --ips IPS     File containing list of IPs
  -d DOMAINS, --domains DOMAINS
                        File containing list of domains
  -o OUTPUT, --output OUTPUT
                        File to save the bypass results (optional)
  -t, --threads THREADS
                        Number of threads to use (default is 5)
```