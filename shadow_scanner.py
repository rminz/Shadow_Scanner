import requests
import sys
import json
import os
import configparser
from configparser import ConfigParser
import time
import re
import argparse

AUTHOR = "ARMIN ZIAIE TABARI"
VERSION = "v1.0"

#Add all Anti Virus's Vendors in Virustotal website
ANTIVIRUS =['Bkav','MicroWorld-eScan','CMC','CAT-QuickHeal','McAfee',
           'Malwarebytes','Zillya','SUPERAntiSpyware','TheHacker',
           'K7GW','K7AntiVirus','Baidu','NANO-Antivirus','F-Prot',
           'Symantec','ESET-NOD32','TrendMicro-HouseCall','Avast',
           'ClamAV','Kaspersky','BitDefender','Babable','AegisLab',
           'Rising','Ad-Aware','Emsisoft','F-Secure','DrWeb','VIPRE',
           'TrendMicro','McAfee-GW-Edition','Sophos','Cyren','Jiangmin',
           'Avira','Fortinet','Antiy-AVL','Kingsoft','Arcabit','ViRobot',
           'AhnLab-V3','ZoneAlarm','Avast-Mobile','Microsoft','TACHYON',
           'TotalDefense','VBA32','ALYac','MAX','Zoner','Tencent','Yandex',
           'Ikarus','GData','AVG','Panda','Qihoo-360']

Sleep_Time = 15 #We set wait time to 15 seconds because, Public API only can handle 4 request per minute.

class Colors:
    REDBG = '\033[41m'
    GREENBG = '\033[42m'
    ORANGEBG = '\033[43m'
    CWHITEBG = '\33[47m'
    CWHITE  = '\33[37m'
    CVIOLETBG2 = '\33[105m'
    VIRUSBG = '\33[107m'
    CBLACKBG = '\33[7m'
    END = '\033[0m'

class Fields:
    HASH = Colors.CBLACKBG+"Hash:"+Colors.END+" "
    VERBOS_MSG = Colors.CBLACKBG+"Verbos MSG:"+Colors.END+" "
    FileName = Colors.CBLACKBG+"Filename:"+Colors.END+" "
    Virus = Colors.CBLACKBG+"Virus:"+Colors.END+" "
    Last = Colors.CBLACKBG+"Scan date:"+Colors.END+" "
    First = Colors.CBLACKBG+"First time visited:"+Colors.END+" "

def get_score(response):
    try:
        code_resp = response.json()['response_code']
    except Exception as e :
        print("error")

    if code_resp == 0:
        return Colors.CWHITEBG+"Unknown"
    elif 0 < response.json()['positives'] <= 1:
        return '\033[43m'+"Suspicious"
    elif 1 < response.json()['positives'] :
        return Colors.REDBG+"Malicious"
    elif response.json()['positives'] == 0:
        return'\033[42m'+"clean"


def get_info(resp):
    response = resp.json()
    vt_info = {
        "hash" : "*",
        "results" : "*",
        "virus" : "",
        "filename" : "*",
        "positives" : 0,
        "filetype" : "*",
        "first_visited" : "*",
        "last_visit" : "*",
        "verbos_msg" : "*",
        "total" : 0,
        "response_code" : 0,
    }
    vt_info["hash"] = response.get("sha256")
    vt_info["positives"] = response.get("positives")
    vt_info["filename"] = response.get("filename")
    vt_info["verbose_msg"] = response.get("verbose_msg")
    vt_info["last_visit"] = response.get("scan_date")
    vt_info["total"] = response.get("total")
    vt_info["response_code"] = response.get("response_code")
    if vt_info["response_code"] == 1:
        for anti in ANTIVIRUS:
            if anti in response.get("scans"):
                if vt_info["positives"] > 0:
                    if response["scans"][anti]["detected"]:
                        vt_info["virus"] += Colors.VIRUSBG + str(anti) + Colors.END + \
                        " : "+str(response["scans"][anti]["result"])+" "
                else:
                    vt_info["virus"] = " clean "
    else:
        vt_info["virus"] = " unknown "

    vt_results_head = str(get_score(resp))+" "+str(vt_info["positives"])+" > "+str(vt_info["total"]) + "\n" +Colors.END
    vt_results_body = str(Fields.HASH) + str(vt_info["hash"])+ " " + \
                        str(Fields.VERBOS_MSG) + str(vt_info["verbose_msg"]) + " " + \
                        str(Fields.FileName) + str(vt_info["filename"]) + " " + \
                        str(Fields.Last) + str(vt_info["last_visit"]) + "\n" + \
                        "{ "+str(Fields.Virus) + str(vt_info["virus"]+ " }")
    vt_results = vt_results_head + vt_results_body
    return vt_results

def print_output(response):

    try:
        respe = response.json()
        vt_info = get_info(response)
        print(str(vt_info)+"\n")

    except JSONDecodeError as e:
        print(Colors.REDBG+"[Error]: "+Colors.END+"Cannot handle the response")



if __name__ == '__main__':
    print("   _____ _               _                  _____                                 ".center(40))
    print("  / ____| |             | |                / ____|                                ".center(40))
    print(" | (___ | |__   __ _  __| | _____      __ | (___   ___ __ _ _ __  _ __   ___ _ __ ".center(40))
    print("  \___ \| '_ \ / _` |/ _` |/ _ \ \ /\ / /  \___ \ / __/ _` | '_ \| '_ \ / _ \ '__|".center(40))
    print("  ____) | | | | (_| | (_| | (_) \ V  V /   ____) | (_| (_| | | | | | | |  __/ |   ".center(40))
    print(" |_____/|_| |_|\__,_|\__,_|\___/ \_/\_/   |_____/ \___\__,_|_| |_|_| |_|\___|_|   ".center(40))
    print(" ")
    print("Virustotal Online Scanner [Hash]".center(75))
    print((" "+AUTHOR+ " - "+VERSION+"\n").center(75))

    config = configparser.ConfigParser()
    try:
        config.read('conf.cfg')
        VT_API_KEY = config['API_KEY']['VT_API_KEY']

    except:
        print(Colors.REDBG+"[Error]: "+Colors.END+"Config file not found")
        sys.exit(1)

    #Check API key format
    if VT_API_KEY == "" or not re.match(r"^[0-9a-fA-F]{64}$",VT_API_KEY):
        print(Colors.REDBG+"[Error]: "+Colors.END+"API key format is not correct")
        sys.exit(1)

    #Add argument to the file
    parser = argparse.ArgumentParser()
    parser.add_argument("-i", help="Input file to process Hash code")
    arguments = parser.parse_args()
    #Read Hashes from File
    if arguments.i =="":
        print(Colors.REDBG+"[Error]: "+Colors.END+"Provide an input file for process [Use -i filename]")
        sys.exit(1)
    else:
        try:
            with open(arguments.i,'r', newline=None) as file:
                for line in file:
                    params = {
                        'apikey': VT_API_KEY,
                        'resource': line
                        }
                    response = requests.get('https://www.virustotal.com/vtapi/v2/file/report', params=params)
                    print_output(response)
                    #sleep time
                    time.sleep(Sleep_Time)
        except Exception as excp:
            print(Colors.REDBG+"[Error]: "+Colors.END+"Provide an input file for process [Use -i filename]")
            sys.exit(1)
