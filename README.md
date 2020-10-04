<p align="center">
<a href="https://github.com/txsadhu/domfu"><img src="https://i.imgur.com/xYoBNoF.png" alt="DomFu logo"></a>
</p>

<p align="center">
  <a href="https://www.python.org/download/releases/3.8">
    <img src="https://img.shields.io/badge/Python-3.8-green.svg">
  </a>
  <a href="https://github.com/txsadhu/domfu/releases">
    <img src="https://img.shields.io/badge/DomFu-v1.1-violet.svg">
  </a>
  <a href="https://github.com/txsadhu/domfu/">
      <img src="https://img.shields.io/badge/Tested%20on-Linux-yellow.svg">
  </a>
  <a href="https://github.com/TxSadhu/DomFu/blob/master/LICENSE.txt">
    <img src="https://img.shields.io/badge/License-GPLv3-orange.svg">
  </a> 
  <a href="https://github.com/TxSadhu/DomFu/releases/tag/v1.1.0/">
    <img src="https://img.shields.io/badge/Release-Stable-green.svg">
  </a>
</p>

---

A python module to find domains and subdomains of a given domain with a easy to use CLI.

## Installation

**Using pip:**

```bash
$ sudo apt-get update -y
$ sudo pip install DomFu
```

**Manual Installation:**

```bash
$ git clone https://github.com/TxSadhu/DomFu.git
$ cd DomFu
$ sudo python setup.py install
```

## Update

**Using pip:**

```bash
$ sudo apt-get update -y
$ sudo pip install DomFu==1.2.2
```

**Manual Installation:**

```
$ git clone https://github.com/TxSadhu/DomFu.git
$ cd DomFu
$ sudo python setup.py install
```

## Usage

**Using as Standalone CLI app:**

```bash
domfu --help
```

**Using it as a python module:**

```python
import DomFu as df

dom = "tropyl.com"

# Using all sources:
df.subdomain(dom)

# Using individual sources to find subdomain:
df.fetchCrtSh(dom)
df.fetchBufferOverRun(dom)
df.fetchHackerTarget(dom)
df.fetchThreatCrowd(dom)
df.fetchVirusTotal(dom)

# Check if a list of domain is vaild:
dom_lst = ['tropyl.com', 'www.tropyl.com', 'fake.tropyl.com']
df.Probe(dom _lst)

```

## Features:

- Fetches subdomain of a domain in the fastest possible time.
- Built-in domain prober, useful when you want to validate your subdomains.
- Can be used inside any python code by importing the module.

## Contributing

See the .todo file and get started with any of the upcoming changes you want to make.

Pull requests are welcome. For major changes, please open an issue first to discuss what you would like to change. Please make sure to update everything as appropriate.

**Note: Do not ever make a direct pull request to the master branch. Switch to the dev branch to look for active development going on the tool.**
