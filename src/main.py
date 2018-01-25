#!/usr/bin/python3
'''
Vortex AI - ED-209 - HTTP Gathering Assistent  
Headless access to resource.

Author: Glaudson Ocampos - <glaudson@vortex-ai.com.br>
'''
'''
Chrome headless has problems with SSL Certificate invalids.
So, I am using Firefox WebDriver. Install GeckoDriver:

https://github.com/mozilla/geckodriver/releases

Tested in Linux Ubuntu 16.04 LTS and Python 3.6.
'''

import time
import re
import sys,os
from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.common.exceptions import TimeoutException
from selenium.webdriver.firefox.firefox_binary import FirefoxBinary

import signal
from datetime import datetime
import requests
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)



#firefox ubuntu only works with environment variable
os.environ['MOZ_HEADLESS'] = '1'

FIREFOX_BIN="/usr/bin/firefox"
CHROME_BIN="/usr/bin/google-chrome"
USER_AGENT="Mozilla/5.0 (Windows NT 6.1; WOW64; rv:52.0) Gecko/20100101 Firefox/52.0"
ACCEPT="text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"
ACCEPT_LANGUAGE="pt-BR,pt;q=0.8,en-US;q=0.5,en;q=0.3"
ACCEPT_ENCODING="gzip, deflate, br"


class HeadlessGathering(object):
    urlTarget = ''
    driver = ''
    session = ''
    proxies = ''

    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update({'User-Agent': USER_AGENT, 'Accept': ACCEPT, 'Accept-Language': ACCEPT_LANGUAGE, 'Accept-Encoding': ACCEPT_ENCODING})
        self.session.headers.update({'DNT': '1', 'Upgrade-Insecure-Requests':'1'})
        self.charset = "utf-8"
        #self.proxies = {'https':'192.168.2.100:8080'}

    def set_urlTarget(self, val):
        self.urlTarget = val
    def get_urlTarget(self):
        return self.urlTarget

    def init_driver(self):
        binary = FirefoxBinary(FIREFOX_BIN)
        self.driver = webdriver.Firefox(firefox_binary=binary)
        self.driver.wait = WebDriverWait(self.driver, 4)
        return self.driver

    def get_cookies(self):
        print("\t+ Getting Cookies.")
        file0 = self.urlTarget.replace("/", "") 
        file1 = file0.replace(":","_") 
        filename = 'cookies/' + file1 + ".txt"

        file = open(filename,'w') 
        all_cookies = self.driver.get_cookies()
        
        for c in all_cookies:
            msg = str(c) +  "\n"
            file.write(msg)
        file.close()
        
 
    def get_headers(self):
        print("\t+ Getting Response Headers.")
        file0 = self.urlTarget.replace("/", "") 
        file1 = file0.replace(":","_") 
        filename = 'headers/' + file1 + ".txt"
        file = open(filename,'w') 
        r = self.session.get(self.urlTarget, verify=False, proxies=self.proxies, allow_redirects=False)
        http_version = r.raw.version
        if http_version == 10:
            version = "1.0"
        if http_version == 11:
            version = "1.1"
        if http_version == 20:
            version = "2.0"
            
        msg = 'HTTP/' + str(version) + ' ' +  str(r.status_code) + ' ' + str(r.reason) + "\n"
        file.write(msg)
        for h in r.headers:
            msg = str(h) + ":" + str(r.headers[h]) + "\n"
            file.write(msg)
        file.close()
 
    def get_screenshot(self):
        print("\t+ Getting Screenshot.")
        file0 = self.urlTarget.replace("/", "") 
        file1 = file0.replace(":","_") 
        filename = 'screenshots/' + file1 + ".png"
        self.driver.set_window_size(1280,1696)
        self.driver.save_screenshot(filename)
 
 
    def run(self):
        print("URL Target: " + self.urlTarget)
        self.driver = self.init_driver()
        self.driver.get(self.urlTarget)
        self.driver.implicitly_wait(10)

        self.get_screenshot()
        self.get_cookies()
        self.get_headers()

        self.driver.close()
        


def runHG(urlfile):
    print("Running Gathering Information...\n")
    hg = HeadlessGathering()
    uFile = open(urlfile)
    
    for u in uFile.read().split('\n'):
        if u is not '':
            hg.set_urlTarget(u)
            hg.run()
        
    print("Attack Finished.")

def handler(signum, frame):
    print("\n\nStop execution...", signum);
    sys.exit(0)
    

def show_ed209():
    f = open("./ed209.asc","r")
    print(f.read())
    f.close()     

def show_help():
    print("Vortex-AI - ED-209 - Gathering infos using headless")
    print("http://www.vortex-ai.com.br/\n")
    show_ed209()
    print("Usage: python3  " + __file__ + " <url.txt>\n")
    print("Example:\n")
    print("python3 " + __file__ + " urls.txt")
    
    

def main(args):
    signal.signal(signal.SIGINT, handler)
    if args is None:
        show_help()
    else:
        runHG(args[0])
        
if __name__ == '__main__':
    if len(sys.argv) == 1:
        show_help()
    else:
        main(sys.argv[1:])
    
