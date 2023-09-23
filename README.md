# FTP Scanner

FTP Scanner is a Python script that scans a specified IP range in CIDR notation to identify FTP servers with or without anonymous access. It can also optionally download files from FTP servers that allow anonymous access.

## Table of Contents
- [Features](#features)
- [Prerequisites](#prerequisites)
- [Usage](#usage)
- [Example](#example)
- [License](#license)

## Features

- Scans a specified IP range in CIDR notation for FTP servers.
- Identifies whether FTP servers allow anonymous access or not.
- Can download files from FTP servers that allow anonymous access.
- Multithreaded scanning for faster results.

## Prerequisites

Before you begin, ensure you have met the following requirements:

- Python 3.x installed on your system.
- Required Python packages can be installed using `pip`:

  ```bash
  pip install tqdm ftputil netaddr
  ```
## Usage
1. Clone this repository 
```bash
git clone https://github.com/pannagkumaar/FTP-Scanner.git
cd FTP-Scanner
```
2. Run the script using the following command:
```bash
python FTP_Scanner.py -i <IP_range_in_CIDR_notation> [-d] [-t <num_threads>]
```
- **-i** <IP_range_in_CIDR_notation>: Specify the IP range in CIDR notation to scan.
- **-d**: Optionally, use this flag to download files from FTP servers that allow anonymous  access.
- **-t** <num_threads>: Optionally, set the number of threads for scanning (default is 10)
3. Follow the on-screen prompts and view the scan progress.

4. Once the scan is complete, the script will display the FTP servers found with and without anonymous access.

5. If the -d flag was used, all anonymous FTP files will be copied to a folder named 'FTP-Scanner_data' in the current working directory.

## Example
```bash
python ftp_scanner.py -i 192.168.1.0/24 -d -t 20
```
This command will scan the IP range 192.168.1.0/24 with 20 threads, identify FTP servers with anonymous access, and download files from those servers.
