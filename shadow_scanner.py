import requests
import sys
import json
import os
import configparser
from configparser import ConfigParser
import time
import re
import argparse
import VTScanner
import IPAbuseChecker
from IPAbuseChecker import check_IP
from constant import Colors

AUTHOR = "ARMIN ZIAIE TABARI"
VERSION = "v2.1"


if __name__ == '__main__':
    print("   _____ _               _                  _____                                 ".center(40))
    print("  / ____| |             | |                / ____|                                ".center(40))
    print(" | (___ | |__   __ _  __| | _____      __ | (___   ___ __ _ _ __  _ __   ___ _ __ ".center(40))
    print("  \___ \| '_ \ / _` |/ _` |/ _ \ \ /\ / /  \___ \ / __/ _` | '_ \| '_ \ / _ \ '__|".center(40))
    print("  ____) | | | | (_| | (_| | (_) \ V  V /   ____) | (_| (_| | | | | | | |  __/ |   ".center(40))
    print(" |_____/|_| |_|\__,_|\__,_|\___/ \_/\_/   |_____/ \___\__,_|_| |_|_| |_|\___|_|   ".center(40))
    print(" ")
    print((" "+AUTHOR+ " - "+VERSION+"\n").center(75))
    
    print("1) Virustotal Online Scanner [Hash]")
    print("2) AbuseIPDB Scanner")
    print("3) Metadefender IP Scanner")
    print("4) Exit")
    
    try:
        choice = int(input('[*] Enter your choice: '))
        if choice == 1:
            FileName = input('[-] Enter your file name: ')
            if FileName == "":
                print(Colors.REDBG+"[Error]: "+Colors.END+"Provide an input file for process")
                sys.exit(1)
            else:
                VTScanner.main(FileName)
                sys.exit(1)
        elif choice == 2:
            file = input('[-] Enter your file name: ')
            if file == "":
                print(Colors.REDBG+"[Error]: "+Colors.END+"Provide an input file for process")
                sys.exit(1)
            else:
                IPAbuseChecker.check_IP(file)
        elif choice == 3:
            print("Coming Soon...")
            
        elif choice == 4:
            print("[*] Exiting... ")
            sys.exit(1)
        else:
            print("[*] Invalid choice")
            sys.exit(1)
    except KeyboardInterrupt:
        sys.exit(1)

