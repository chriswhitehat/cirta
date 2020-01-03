import re
import requests

def mac_check(mac_address):

    try:
        url = "https://api.macvendors.com/"
        regex = "[0-9A-Za-z]{2}[:-][0-9A-Za-z]{2}[:-][0-9A-Za-z]{2}[:-][0-9A-Za-z]{2}[:-][0-9A-Za-z]{2}[:-][0-9A-Za-z]{2}|[a-zA-Z0-9]{4}\.[a-zA-Z0-9]{4}\.[a-zA-Z0-9]{4}"
        valid_mac = re.findall(regex,mac_address)
        url = url + valid_mac[0]
        s = requests.Session()
        r = s.get(url, verify=False)
        return  r.text

    except ValueError as error:

        print("%s" % (error))






