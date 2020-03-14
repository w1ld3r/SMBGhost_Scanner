# SMBGhost
Advanced scanner for CVE-2020-0796 - SMBv3 RCE using [ollypwn](https://github.com/ollypwn) detection technique ([SMBGhost](https://github.com/ollypwn/SMBGhost)).

It can scan the entire internet using masscan or, a single ip.

It can get more informations about targets using Shodan (API key required) and write results to json file.

Otherwise, it will print vulnerable ip on the console.

## Getting Started
### Prerequisites

Install python3 and pip:
```
sudo apt install python3 python3-pip
```

Install masscan:
```
sudo apt-get install git gcc make libpcap-dev
git clone https://github.com/robertdavidgraham/masscan
cd masscan
make
cp bin/masscan /usr/bin/.
```

### Installing
The installation has been tested in Debian bullseye/sid x86_64 (march 2020)
#### Clone the project
```
git clone https://github.com/x1n5h3n/SMBGhost.git
```

#### Move in the project folder
```
cd SMBGhost
```

Install the necessary Python packages:
```
pip3 install -r requirements.txt
```

Set your Shodan API key to the variable **SHODAN_API_KEY**

### Usage
Print help:
```
python3 scanner.py -h
```

#### With a Shodan API key
Scann the entire Internet and write results in json file (using querry to shodan to gather more informations):
```
python3 scanner.py -t 0.0.0.0/0 -o results.json
```

Scann a single ip without specifying the result filename (default is smbghost.json):
```
python3 scanner.py -t 8.8.8.8
```

Using a file as input:
```
python3 scanner.py -f targets.txt
```

#### Without a Shodan API key
Scann the entire Internet:
```
python3 scanner.py -t 0.0.0.0/0
```

Scann a single ip:
```
python3 scanner.py -t 8.8.8.8
```

Using a file as input:
```
python3 scanner.py -f targets.txt
```

## Authors

* **[x1n5h3n](https://blog.xinshen.se/about)**

## License

This project is licensed under the GPLv3 License - see the [LICENSE](LICENSE) file for details.

