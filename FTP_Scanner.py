import sys
from multiprocessing import Pool, freeze_support
from tqdm import tqdm
from ftplib import FTP
from ftplib import error_perm
from netaddr import *
import os
import argparse
from platform import system
import re
import socket

# Function to verify if input CIDR notated string is a real network
def cidr_verify(cidr_address):
    try:
        if re.match('^([0-9]{1,3}\.){3}[0-9]{1,3}(\/([0-9]|[1-2][0-9]|3[0-2]))?$', cidr_address) is not None:
            split_address = cidr_address.split('/')
            socket.inet_aton(split_address[0])
            if int(split_address[1]) <= 32:
                return cidr_address
            else:
                print('CIDR notation incorrect. Netmask must be /32 or lower.')
                sys.exit()
        else:
            print('Unknown CIDR address. Verify input is in correct format (192.168.1.0/24, for example).')
            sys.exit()
    except:
        print('Error parsing CIDR address. Verify netmask is specified in input (use /32 for a single IP scan).')
        sys.exit()

# Function to check if anonymous access is allowed
def check_anonymous_access(ip):
    try:
        ftp = FTP(ip, timeout=5)
        response = ftp.sendcmd("USER anonymous")
        ftp.quit()

        if "331" in response:
            return True  
        else:
            return False  

    except error_perm:
        return False  # FTP server returned an error, anonymous access not allowed
    except socket.error:
        return False  # Could not connect to the FTP server
    except:
        return False  # Other exceptions


def execute_scan(ip):
    try:
        anonymous_access_allowed = check_anonymous_access(str(ip))
        
        if anonymous_access_allowed:
            ftp = FTP(str(ip), timeout=5)
            ftp.login('anonymous', 'anonymous@test.com') 
            ftp.quit()
            return str(ip)
        else:
            return "{}|FTP_NoAnon".format(str(ip))

    except error_perm:
        ftp.quit()
        return "{}|FTP_NoAnon".format(str(ip))
    except:
        return

# Parse through each file and directory in FTP structure and copy to local system
def download_files(f_ip):
    i = 0
    try:
        items = []
        f_ftp = FTP(str(f_ip), timeout=5)
        f_ftp.login('anonymous', 'anonymous@test.com')
        f_ftp.retrlines('LIST', items.append)
        items = map(str.split, items)
        directories = [item.pop() for item in items if item[0][0] == 'd']

        file_names = f_ftp.nlst()

        if file_names:
            os.makedirs('FTP-Scanner-data/{}'.format(f_ip))

        for file_name in file_names:
            if file_name not in directories:
                local_file = os.path.normpath('FTP-Scanner-data/{}/{}'.format(f_ip, file_name))
                if os.path.exists(local_file):
                    local_file = os.path.join('{}.{}'.format(local_file, i))
                    i += 1
                with open(local_file, 'wb') as d_file:
                    f_ftp.retrbinary('RETR {}'.format(file_name), d_file.write)

        for directory in directories:
            if not os.path.exists('FTP-Scanner-data/{}/{}'.format(f_ip, directory)):
                os.makedirs('FTP-Scanner-data/{}/{}'.format(f_ip, directory))
            download_files_recursive(f_ftp, directory, f_ip, directory)
    except:
        return

# Iterate through all sub-folders in FTP directory and write files to their appropriate local versions
def download_files_recursive(r_ftp, r_dir, r_ip, directory):
    r_ftp.cwd(r_dir)
    items = []
    r_ftp.retrlines('LIST', items.append)
    items = map(str.split, items)
    directories = [item.pop() for item in items if item[0][0] == 'd']

    file_names = r_ftp.nlst()

    for file_name in file_names:
        if file_name not in directories:
            local_file = os.path.normpath('FTP-Scanner-data/{}/{}/{}'.format(r_ip, directory, file_name))
            with open(local_file, 'wb') as d_file:
                r_ftp.retrbinary('RETR {}'.format(file_name), d_file.write)

    for directory in directories:
        if not os.path.exists('FTP-Scanner-data/{}/{}'.format(r_ip, directory)):
            os.makedirs('FTP-Scanner-data/{}/{}'.format(r_ip, directory))
        download_files_recursive(r_ftp, directory, r_ip, directory)
        r_ftp.cwd('..')

# Function to clear the screen
def clear_screen():
    if system().lower() == 'windows':
        os.system('cls')
    else:
        os.system('clear')

# Main function
if __name__ == "__main__":
    # If the system is non-Windows, import readline for easier input
    if system().lower() != 'windows':
        import readline

    # Clear the screen
    clear_screen()

    # Declare array variables
    anon_array = []
    non_anon_array = []

    # Print banner
    print('\n')
    print('#' * 80)
    print(' ' * 20 + 'FTP-Scanner - Anonymous FTP Scanner')
    print('#' * 80 + '\n')

    # Argument parsing commands
    parser = argparse.ArgumentParser()
    parser.add_argument('-i', '--ip', help='IP range to scan (CIDR Notation)')
    parser.add_argument('-d', '--download', help='If anonymous access allowed, download all files on FTP share', action='store_true')
    parser.add_argument('-t', '--threads', help='Number of threads to scan from (Default: 10)')
    args = parser.parse_args()

    # Ask for CIDR network range if not passed via argument, then verify proper CIDR notation
    if args.ip is None:
        ipRange = input('Please enter IP range to scan (CIDR notation): ')
        verRange = cidr_verify(ipRange)
    else:
        ipRange = args.ip
        verRange = cidr_verify(ipRange)

    # Set number of threads to scan with if passed via argument, otherwise default to 10
    if args.threads:
        num_threads = args.threads
    else:
        num_threads = 10

    # Check to see if files should be downloaded
    download_status = args.download

    # Configure CIDR notated string to IPNetwork
    ip = IPNetwork(verRange)

    # Set up multithreading pools
    freeze_support()
    pool = Pool(processes=int(num_threads))

    print('Breaching {} IP range with {} threads...\n'.format(verRange, num_threads))

    # Multithread FTP connections and display progress bar
    for addr in tqdm(pool.imap_unordered(execute_scan, ip), total=len(ip), ascii=True, desc='Progress: ',
                     bar_format='{l_bar}{bar}| {n_fmt}/{total_fmt} Remaining: {remaining}', ncols=80, leave=False):
        if addr:
            if "|FTP_NoAnon" in addr:
                non_anon = addr.split('|')
                non_anon_array.append(non_anon[0])
            else:
                anon_array.append(addr)
                if download_status:
                    download_files(addr)

    print('FTP Servers Found w/ Anonymous Access: {}'.format(','.join(anon_array)))
    print('FTP Servers Found w/o Anonymous Access: {}'.format(','.join(non_anon_array)))

    if download_status:
        print('\nAll anonymous FTP files have been copied to folder \'FTP-Scanner_data\' in the current working directory.')
