try:
    import json
    import requests
    import urllib.parse
    import os
    import re
    import sys
    import time
    from fpdf import FPDF


    def start():
        print("""
      
 ___________________________________________________________________________________________________________
 |                                 ____        __       __                                                 |
 |                                / __ \__  __/ /______/ /____  _____                                      |
 |                               / /_/ / / / / __/ ___/ __/ _ \/ ___/                                      |
 |                              / ____/ /_/ / /_(__  ) /_/  __/ /                                          |
 |                             /_/    \__, /\__/____/\__/\___/_/                                           |
 |                                   /____/                                                                |
 |                                                                                                         |
 |@authors     : Dharineesh.J and Ganesh Balaji.V                                                          |
 |@Description : This tool helps to fetch the data about how secure a URL (or) an IP (or) a domain is. It  |
 |               collects the data from various OSINT websites and stores it in a file in the user path.   |
 |               It also checks whether an email is valid and checks whether the entered hash value is     |
 |               malicious.                                                                                |
 |                                                                                                         |
 |_________________________________________________________________________________________________________|
      
      """)

    def create_pdf(input_file):
        pdf = FPDF()
        pdf.add_page()
        pdf.set_font('Arial','BI',20)
        pdf.set_xy(50,10)
        pdf.cell(100,20,'Pytster Report',0,1,'C')
        pdf.set_xy(0,40)
        pdf.set_font('arial', size=10)
        info=""
        with open(input_file, 'r', encoding='utf-8') as text_file:
            for line in text_file:
                info+=line
        text = info.encode('latin-1', 'replace').decode('latin-1')
        pdf.multi_cell(0, 5,text)
        pdf.output(os.path.join(os.getcwd(),'result.pdf'))

    def create_JSON(input_file):
        dict = []
        with open(input_file,encoding="utf-8") as fh:
            for line in fh:
                command = line.strip().split(None, 1)
                dict.append(command)
        out_file = open(os.path.join(os.getcwd(),'result.json'), "w")
        json.dump(dict, out_file, indent = 4, sort_keys = False)
        out_file.close()
    
    def domain(dom):
        domain_regex_pattern = r"^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$"
        if re.match(domain_regex_pattern, dom):
            #IP2WHOIS
            url="https://api.ip2whois.com/v2?key=B14E1C337A4BA087E8005CC9E21068FD&domain="+dom
            response=requests.get(url)
            response_text=response.json()
            with open(os.path.join(os.getcwd(),'result.txt'),'wb') as f:
                f.write(b"Websites:-\n1. IP2WHOIS\n2. Whoisfreaks\n3. VirusTotal\n4. DomainSDB\n")
                f.write(b"-----------------------------------------------------------------------------------------------------------------\n\n")
                f.write("IP2WHOIS:\n".encode("utf-8"))
                for k,v in response_text.items():
                    f.write(f"{k}:{v}\n".encode("utf-8"))
                f.write(b"-----------------------------------------------------------------------------------------------------------------\n\n")


            #Virustotal
            url=f"https://www.virustotal.com/api/v3/domains/"+dom
            headers={'x-apikey':'74103328471597f0a659056c7db646b919809c3e57231b7e2a04a8b339966a5b'}
            response=requests.get(url,headers=headers)
            detected_undetected=[]
            if response.status_code==200:
                response_dict=response.json()
                for i in response_dict['data']['attributes']['last_analysis_results'].values():
                    detected_undetected.append(i['category'])
                print('Virustotal: Not Malicious' if detected_undetected.count('undetected')>detected_undetected.count('malicious') or detected_undetected.count('harmless')>detected_undetected.count('malicious')  else 'Virustotal: Malicious')
                with open(os.path.join(os.getcwd(),'result.txt'),'ab') as f:
                    f.write("Virustotal:\n".encode("utf-8")+response.text.encode("utf-8"))
                    f.write(b"-----------------------------------------------------------------------------------------------------------------\n\n")


            #Domainsdb
            url="https://api.domainsdb.info/v1/domains/search?domain="+dom
            response=requests.get(url)
            if response.status_code==200:
                response_text=response.json()
                with open(os.path.join(os.getcwd(),'result.txt'), 'ab') as f:
                    f.write("DomainsDB:\n".encode("utf-8"))
                    for i in response_text:
                        f.write(f"{i}\n".encode("utf-8"))
                    f.write(b"-----------------------------------------------------------------------------------------------------------------\n\n")


            #WhoisFreaks 
            url="https://api.whoisfreaks.com/v1.0/whois?apiKey=2179d3848cd546a7a2a9ece02f347472&whois=live&domainName="+dom
            response=requests.get(url)
            if response.status_code==200:
                response__text=response.json()#['registry_data']
                with open(os.path.join(os.getcwd(),'result.txt'), 'ab') as f:
                    f.write(f"WHOISfreaks:\n".encode("utf-8"))
                    for keys,values in response__text.items():
                        if keys!='whois_raw_registery' and keys!='registry_data':
                            f.write(f"{keys}:{values}\n".encode("utf-8"))
                    f.write(b"\n-----------------------------------------------------------------------------------------------------------------\n\n")        
        
            create_pdf(os.path.join(os.getcwd(),'result.txt'))
            create_JSON(os.path.join(os.getcwd(),'result.txt'))
            print(f"\n\nReport files are stored in {os.getcwd()}...")

        else:
            print("Entered domain name is invalid...")
            exit(0)


    def ip(ip_):
        ip_regex_pattern="""^\\b(?:\\d{1,3}\\.){3}\\d{1,3}\\b"""
        if re.match(ip_regex_pattern, ip_):
            #IP2LOCATION
            url="https://api.ip2location.io/?key=30487B996FCEC3465AE86621F2803BC8&ip="+ip_
            response=requests.get(url)
            if response.status_code==200:
                response_dict=response.json()
                print("IP2Location: No Proxy" if response_dict['is_proxy']=='False' else "IP2Location: Proxy ip")
                with open(os.path.join(os.getcwd(),'result.txt'),'wb') as f:
                    f.write(b"Websites:-\n1. IPstack\n2. IP2location\n3. IPapi\n4. Whatismyip.com\n")
                    f.write(b"\n-----------------------------------------------------------------------------------------------------------------\n\n")     
                    f.write("IP2LOCATION:\n".encode("utf-8"))
                    for k,v in response_dict.items():
                        f.write(f"{k}:{v}\n".encode("utf-8"))
                    f.write(b"\n-----------------------------------------------------------------------------------------------------------------\n\n")     
        

            #Whatismyip
            api_key = '0270ce5e12f1adff8f18a00d2d0a7164'#Whatismyip.com
            url = f"https://api.whatismyip.com/ip-address-lookup.php?key={api_key}&input={ip_}"
            r = requests.get(url) 
            if response.status_code==200:
                print("Whatismyip.com:",r.text[0:10])
                with open(os.path.join(os.getcwd(),'result.txt'),'ab') as f:
                    f.write("Whatismyip:\n".encode("utf-8")+r.text.encode("utf-8"))
                    f.write(b"\n-----------------------------------------------------------------------------------------------------------------\n\n")     
        
            #IPstack
            url=f"http://api.ipstack.com/{ip_}?access_key=e07ede4bdad639c796afdce7dfc42261"
            response=requests.get(url)
            if response.status_code==200:
                response_dict=response.json()
                with open(os.path.join(os.getcwd(),'result.txt'),'ab') as f:
                    f.write("IPstack:\n".encode("utf-8"))
                    for k,v in response_dict.items():
                        f.write(f"{k}:{v}\n".encode("utf-8"))
                    f.write(b"\n-----------------------------------------------------------------------------------------------------------------\n\n")


            #IPapi
            url=f'http://api.ipapi.com/api/{ip_}/?access_key=4d032ece7620cc1d3e015045e4b6ac61'
            response=requests.get(url)
            if response.status_code==200:
                with open(os.path.join(os.getcwd(),'result.txt'),'ab') as f:
                    f.write("IPapi:\n".encode("utf-8"))
                    for k,v in response.json().items():
                        f.write(f"{k}:{v}\n".encode("utf-8"))
                    f.write(b"\n-----------------------------------------------------------------------------------------------------------------\n\n")
                
            create_pdf(os.path.join(os.getcwd(),'result.txt'))
            create_JSON(os.path.join(os.getcwd(),'result.txt'))

            print(f"\n\nReport files are stored in {os.getcwd()}...")


        else:
            print("Entered IPv4 address is invalid...")
            exit()


    def email(email_):
        email_regex_pattern = "^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$"
        if re.match(email_regex_pattern, email_):
            #hunter
            url = f"https://api.hunter.io/v2/email-verifier?email={email_}&api_key=5f3c5a3a11b1b849b3a55fd350310f5ce0c8f1a1"
            response = requests.get(url)
            if response.status_code==200:
                response_dict=response.json()['data']
                print("API Hunter: Disposable-",response_dict['disposable'])
                with open(os.path.join(os.getcwd(),'result.txt'),'wb') as f:
                    f.write(b"Websites:-\n1. ATdata\n2. Hunter\n")
                    f.write(b"\n-----------------------------------------------------------------------------------------------------------------\n\n")
                    f.write("Hunter\n".encode("utf-8"))
                    for k,v in response_dict.items():
                        f.write(f"{k}:{v}\n".encode("utf-8"))
                    f.write(b"\n-----------------------------------------------------------------------------------------------------------------\n\n")

    
            #ATdata
            url = "https://api.atdata.com/v5/ev"
            querystring = {"email":email_,"api_key":"84e5a068cb7122e03f44e97ac80ebb36"}
            response = requests.get(url, params=querystring)
            if response.status_code==200:
                print("ATdata: Domain-type:",response.json()['email_validation']['domain_type'])
                with open(os.path.join(os.getcwd(),'result.txt'),'ab') as f:
                    f.write("ATdata\n".encode("utf-8"))
                    for k,v in response_dict.items():
                        f.write(f"{k}:{v}\n".encode("utf-8"))
                    f.write(b"\n-----------------------------------------------------------------------------------------------------------------\n\n")

            create_pdf(os.path.join(os.getcwd(),'result.txt'))
            create_JSON(os.path.join(os.getcwd(),'result.txt'))
            print(f"\n\nReport files are stored in {os.getcwd()}...")



        else:
            print("Entered email address is invalid...")
            exit(0)

    def url(url_):
            #Virustotal
            url="https://www.virustotal.com/api/v3/urls"
            headers={'x-apikey':'74103328471597f0a659056c7db646b919809c3e57231b7e2a04a8b339966a5b'}
            f_data={'url':url_}
            response=requests.post(url,headers=headers,data=f_data)
            url=json.loads(response.text)['data']['links']['self']
            response=requests.get(url,headers=headers)
            response_dict=response.json()['data']['attributes']['results']
            detected_undetected=[]
            if response.status_code==200:
                for i in response_dict.values():
                    detected_undetected.append(i['category'])
                print('Virustotal: Not Malicious' if detected_undetected.count('undetected')>detected_undetected.count('malicious') or detected_undetected.count('harmless')>detected_undetected.count('malicious')  else 'Virustotal: Malicious')
                with open(os.path.join(os.getcwd(),'result.txt'),'wb') as f:
                    f.write(b"Websites:-\n1. VirusTotal\n2. APIvoid\n3. IPqualityscore\n")
                    f.write(b"\n-----------------------------------------------------------------------------------------------------------------\n\n")
                    f.write("Virustotal:\n".encode("utf-8"))
                    for k,v in response_dict.items():
                        f.write(f"{k}:\t{v}\n".encode("utf-8"))
                    f.write(b"\n-----------------------------------------------------------------------------------------------------------------\n\n")

    
            #APIvoid
            apikey="9ec2f59dcfa5b1324533ebc3370e618c5ce28398"
            url=f"https://endpoint.apivoid.com/urlrep/v1/pay-as-you-go/?key={apikey}&url={url_}"
            response=requests.get(url)
            response_dict=response.json()
            print("APIvoid:",response_dict['data']['report']['domain_blacklist']['engines'][0]['detected'])
            with open(os.path.join(os.getcwd(),'result.txt'),'ab') as f:
                f.write("APIvoid:\n".encode("utf-8"))
                for i in response_dict['data']['report']['domain_blacklist']['engines']:
                    f.write(f"{i}".encode("utf-8"))
                f.write(b"\n-----------------------------------------------------------------------------------------------------------------\n\n")
    
    
            #IPQualityScore
            API_KEY ='Mattw2THyxMjYF3v3sIXDWPIoaDKYg63'
            endpoint = f'https://www.ipqualityscore.com/api/json/url/{API_KEY}/{urllib.parse.quote_plus(url_)}'
            response = requests.get(endpoint)
            response_dict=response.json()
            print("IPQualityScore(url): Suspicious-",response_dict['suspicious'])
            with open(os.path.join(os.getcwd(),'result.txt'),'ab') as f:
                f.write("IPQualityScore:\n".encode("utf-8"))
                for k,v in response.json().items():
                    f.write(f"{k}:{v}\n".encode("utf-8"))
                f.write(b"\n-----------------------------------------------------------------------------------------------------------------\n\n")

            create_pdf(os.path.join(os.getcwd(),'result.txt'))
            create_JSON(os.path.join(os.getcwd(),'result.txt'))
            print(f"\n\nReport files are stored in {os.getcwd()}...")

    def hashify(hash):
        #Virustotal
        url = f"https://www.virustotal.com/api/v3/files/{hash}"
        headers = {
            "accept": "application/json",
            "x-apikey": "74103328471597f0a659056c7db646b919809c3e57231b7e2a04a8b339966a5b"
        }
        response = requests.get(url, headers=headers)
        response__=response.json()
        detected_undetected=[]
        for i in response__['data']['attributes']['last_analysis_results'].values():
            detected_undetected.append(i['category'])
        print('Virustotal: Not Malicious' if detected_undetected.count('undetected')>detected_undetected.count('malicious') else 'Virustotal: Malicious')
        with open(os.path.join(os.getcwd(),'result.txt'),'wb') as f:
            f.write(b"Websites:-\n1. Virustotal\n2. Metadefender\n")
            f.write(b"\n-----------------------------------------------------------------------------------------------------------------\n\n")
            f.write(b"Virustotal:\n")
            for keys,values in response__['data']['attributes']['last_analysis_results'].items():
                f.write(f"{keys}:{values}\n".encode("utf-8"))
            f.write(b"\n-----------------------------------------------------------------------------------------------------------------\n\n")


        #Metadefender
        url = f"https://api.metadefender.com/v5/threat-intel/av-file-reputation/{hash}"
        headers = {"apikey": "59f5f4537b3982f64cc7c0506dffb054",}
        response = requests.get(url, headers=headers)
        print("Metadefender:",response.json()['reputation'])
        with open(os.path.join(os.getcwd(),'result.txt'),'ab') as f:
            f.write(b"Metadefender:\n")
            for keys,values in response.json().items():
                f.write(f"{keys}:{values}\n".encode("utf-8"))
            f.write(b"\n-----------------------------------------------------------------------------------------------------------------\n\n")

        create_pdf(os.path.join(os.getcwd(),'result.txt'))
        create_JSON(os.path.join(os.getcwd(),'result.txt'))
        print(f"\n\nReport files are stored in {os.getcwd()}...")

    
    def help():
        start()
        time.sleep(3)
        print("\n\nThis tool is opened to modification. Only free api keys\nare added in this program. Any changes in the OSINT\nwebsites used and addition of premium api keys are allowed.\n")
        print("\n-h\t - help\n-d\t - search domain\n-u\t - check the security of URL\n-e\t - display the details of particular email\n-i\t - display the details of IPv4 address\n-hs\t - check the safety of the hashes")
        print("\nSample input:\n'python pytster.py -d google.com'")


    pdf=FPDF()
    pdf.add_page()
    pdf.set_font('Arial','BI',20)
    pdf.set_xy(50,10)
    pdf.cell(100,20,'Pytster Report',0,1,'C')
    
    
    options={
        '-h':help,
        '-d':domain,
        '-u':url,
        '-i':ip,
        '-e':email,
        '-hs': hashify
    }
        

    if len(sys.argv)==3 and sys.argv[1] in options:
        start()
        options[sys.argv[1]](sys.argv[2])

    else:
        help()    

except ImportError:
    os.system("pip install re")
    print("\n\nRun the tool again...")

