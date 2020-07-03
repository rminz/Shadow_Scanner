import requests
import sys
import json
import configparser
import time
import re
import constant
from constant import Colors

AbuseIPDB_API_KEY = ""

def Call_API_Key():
    config = configparser.ConfigParser()
    try:
        config.read('conf.cfg')
        AbuseIPDB_API_KEY = config['API_KEY']['AbuseIPDB_APIKEY']

    except:
        print(Colors.REDBG+"[Error]: "+Colors.END+"Config file not found")
        sys.exit(1)

    #Check API key format
    if AbuseIPDB_API_KEY == "" or not re.match(r"^[0-9a-fA-F]{80}$",AbuseIPDB_API_KEY):
        print(Colors.REDBG+"[Error]: "+Colors.END+"API key format is not correct")
        sys.exit(1)
    else:
        return AbuseIPDB_API_KEY
    
def API_CALL(ip,apikey):
    headers = {
        'Key': apikey,
        'Accept': 'application/json',
        }
    parameters = {
        'maxAgeInDays': constant.AbuseIPDB_Days,
        'ipAddress': ip
        }
    api_request = requests.get('https://api.abuseipdb.com/api/v2/check', headers=headers, params=parameters)
    response = api_request.json()
    
    if response['data']['totalReports'] > 0:
        if response['data']['abuseConfidenceScore'] >= 70:
            print(Colors.REDBG + str(response['data']['ipAddress'])+ Colors.END+
              " -> Abuse Confidence Score : "+str(response['data']['abuseConfidenceScore'])
              +", Total Reports : "+ str(response['data']['totalReports'])+
              ", Country Code :"+str(response['data']['countryCode'])+"\n")
        elif 40 <= response['data']['abuseConfidenceScore'] < 70:
            print(Colors.ORANGEBG + str(response['data']['ipAddress'])+ Colors.END+
              " -> Abuse Confidence Score : "+str(response['data']['abuseConfidenceScore'])
              +", Total Reports : "+ str(response['data']['totalReports'])+
              ", Country Code :"+str(response['data']['countryCode'])+"\n")
        else:
            print(str(response['data']['ipAddress'])+
              " -> Abuse Confidence Score : "+str(response['data']['abuseConfidenceScore'])
              +", Total Reports : "+ str(response['data']['totalReports'])+
              ", Country Code :"+str(response['data']['countryCode'])+"\n")
    
def check_IP(files):
    AbuseIPDB_API_KEY = Call_API_Key()
    if files == "":
        print(Colors.REDBG+"[Error]: "+Colors.END+"Provide an input file for process")
    else:
        try:
            with open(files,'r', newline=None) as file:
                for line in file:
                    API_CALL(line,AbuseIPDB_API_KEY)

        except Exception as excp:
            print(Colors.REDBG+"[Error]: "+Colors.END+"Provide an input file for process")
            sys.exit(1)
    