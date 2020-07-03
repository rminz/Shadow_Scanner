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
AbuseIPDB_Days = 90 # Number of days to check the IP through the abuseipdb.com

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


