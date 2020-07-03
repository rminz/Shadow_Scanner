import requests
import sys
import configparser
import time
import re
from json.decoder import JSONDecodeError
import constant
from constant import Colors


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
        for anti in constant.ANTIVIRUS:
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

def main(FileName):
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

    if FileName == "":
        print(Colors.REDBG+"[Error]: "+Colors.END+"Provide an input file for process")
    else:
        try:
            with open(FileName,'r', newline=None) as file:
                for line in file:
                    params = {
                        'apikey': VT_API_KEY,
                        'resource': line
                        }
                    response = requests.get('https://www.virustotal.com/vtapi/v2/file/report', params=params)
                    print_output(response)
                    #sleep time
                    time.sleep(constant.Sleep_Time)
        except Exception as excp:
            print(Colors.REDBG+"[Error]: "+Colors.END+"Provide an input file for process")
            sys.exit(1)

