try:
  #imported Modules
  from fpdf import FPDF
  import requests
  import sys
  import json
  import base64
  import urllib.parse
  import os
  #~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
  '''User's choice whether he wants to scan domain name,ip,email or url and also the input and file path 
     is obtained form a GUI.The input is received with the help of sys module.'''
  i=sys.argv[1]
  choice=sys.argv[2]
  file=sys.argv[3]
  json_con=sys.argv[4]
  pdf_con=sys.argv[5]
  #~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
  '''end(),hint() and write() functions are used for 
     Writing the response from the website in a formated way in a text file
  '''
  def end(file_name):
    with open (file+file_name,'ab') as f:
      f.write(b"--------------------------------------------------------------------------------------------------------------------------------------------------------------------\n\n")
    f.close()
  
  def hint(file_name):
    with open (file+file_name,"wb") as f:
      f.write(b"~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~\n")
      if(choice=="Email-ID"):
          f.write(b"Websites:-\n1.atdata\n2.hunterio\n")
      elif(choice=="URL"):
          f.write(b"Websites:-\n1.VirusTotal\n2.APIvoid\n3.ipqualityscore\n")
      elif(choice=="IP Address"):
          f.write(b"Websites:-\n1.IPstack\n2.Ip2location\n3.ipapi\n4.Whatismyip.com\n")
      elif(choice=="Hash"):
          f.write(b"Websites:-\n1.VirusTotal\n2.Meta defender\n")
      else:
          f.write(b"Websites:-\n1.IP2WHOIS\n2.Whoisfreaks\n3.VirusTotal\n4.DoaminSDB\n")
      f.write(b"~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~\n\n")
    f.close()
    
  def write(file_name,text,mode,Website=None):
    with open (file+file_name,mode) as f:
      if(Website!=None):
        f.write(Website.encode("utf-8")+b"\n")
        for k,v in text.items():
          f.write(f"{k}:{v}\n".encode("utf-8"))
      else:
          for k,v in text.items():
            f.write(f"{k}:{v}\n".encode("utf-8"))
    f.close()
  
  '''This function is used to coverting the text file to pdf'''
  def pdf(input_file, output_file):
    p = FPDF()
    p.add_page()
    p.set_font('Arial','BI',20)
    p.set_xy(50,10)
    p.cell(100,20,'Pytster Report',0,1,'C')
    p.set_xy(0,40)
    p.set_font('arial', size=10)
    info=""
    with open(input_file, 'r', encoding='utf-8') as text_file:
        for line in text_file:
           info+=line
    text = info.encode('latin-1', 'replace').decode('latin-1')
    p.multi_cell(0, 5,text)
    p.output(output_file)

  '''This function is used to create json file from the text file'''
  def JSON(input_file,output_file):
    dict = []
    with open(input_file, 'r', encoding='utf-8') as fh:
        for line in fh:
            command = line.strip().split(None, 1)
            dict.append(command)
    out_file = open(output_file, "w")
    json.dump(dict, out_file, indent = 4, sort_keys = False)
    out_file.close()  

  #~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
  '''Checking E-mail id in various OSINT website 
     Whether it is affected by any malicious attack or not
  '''
  if(choice=="Email-ID"):

    hint("Email_search.txt")
  #website1:atdata
    url = "https://api.atdata.com/v5/ev"
    querystring = {"email":i,"api_key":"84e5a068cb7122e03f44e97ac80ebb36"}
    response = requests.get(url, params=querystring)
    #/
    #print("ATdata: Domain-type:"+response.json()['email_validation']['domain_type'])
    #/
    write("Email_search.txt",response.json()['email_validation'],'ab',"atdata:")
    end("Email_search.txt")

  #Website2:hunterio
    url = f"https://api.hunter.io/v2/email-verifier?email={i}&api_key=5f3c5a3a11b1b849b3a55fd350310f5ce0c8f1a1"
    response = requests.get(url) 
    response_dict=response.json()['data']
    #/
    print("API Hunter: Disposable-",response_dict['disposable'])
    #/
    write("Email_search.txt",response.json()['data'],'ab',"Hunter:")
    end("Email_search.txt")

    if(pdf_con!="0"):
      pdf(file+"Email_search.txt",file+"Email_search.pdf")
    
    if(json_con!="0"):
      JSON(file+"Email_search.txt",file+"Email_search.json")

  #~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    '''Checking Wheather the url is involed in the event and 
       it is safe to use or not
    '''
  elif(choice=="URL"):  
  
    hint("URL_search.txt")
  #Website1:Virustotal
    url="https://www.virustotal.com/api/v3/urls"
    headers={'x-apikey':'74103328471597f0a659056c7db646b919809c3e57231b7e2a04a8b339966a5b'}
    f_data={'url':i}
    response=requests.post(url,headers=headers,data=f_data)
    url=json.loads(response.text)['data']['links']['self']
    response=requests.get(url,headers=headers)
    response_text=response.json()['data']
    #/
    print("Virustotal:",response.json()['data']['attributes']['results']['CMC Threat Intelligence']['category'])
    #/
    write("URL_search.txt",response_text,'ab','Virustotal:')
    end("URL_search.txt")
    
  #Website2:APIvoid
    apikey="9ec2f59dcfa5b1324533ebc3370e618c5ce28398"
    url=f"https://endpoint.apivoid.com/urlrep/v1/pay-as-you-go/?key={apikey}&url={i}"
    response=requests.get(url)
    response_dict=response.json()
    write("URL_search.txt",response_dict['data']['report']['dns_records'],'ab','APIvoid:')
    write("URL_search.txt",response_dict['data']['report']['html_forms'],'ab')
    write("URL_search.txt",response_dict['data']['report']['security_checks'],'ab')
    end("URL_search.txt")

  #Website3:ipqualityscore
    API_KEY ='Mattw2THyxMjYF3v3sIXDWPIoaDKYg63'
    url = f'https://www.ipqualityscore.com/api/json/url/{API_KEY}/{urllib.parse.quote_plus(i)}'
    response = requests.get(url)
    write("URL_search.txt",response.json(),'ab',"ipqualityscore:")
    end("URL_search.txt")

    if(pdf_con!="0"):
      pdf(file+"URL_search.txt",file+"URL_search.pdf")

    if(json_con!="0"):
      JSON(file+"URL_search.txt",file+"URL_search.json")
    
#~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    '''Checking the ip-address obtained from the investigation
       and try to get info of the ip using various OSINT tools
    '''
  elif(choice=="IP Address"):

    hint("IP_search.txt")
  #Website1:IPstack
    url=f"http://api.ipstack.com/{i}?access_key=e07ede4bdad639c796afdce7dfc42261"
    response=requests.get(url)
    write("IP_search.txt",response.json(),'ab','IPstack')
    end("IP_search.txt")

  #Website2:Ip2location
    url="https://api.ip2location.io/?key=30487B996FCEC3465AE86621F2803BC8&ip"+i
    response=requests.get(url)
    #/
    print("IP2Location: No Proxy" if response.json()['is_proxy']=='False' else "IP2Location: Proxy ip")
    #/
    write("IP_search.txt",response.json(),'ab','Ip2location')
    end("IP_search.txt")

  #Website3:ipapi
    url='http://api.ipapi.com/api/8.8.8.8/?access_key=4d032ece7620cc1d3e015045e4b6ac61'
    response=requests.get(url)
    write("IP_search.txt",response.json(),'ab','ipai')
    end("IP_search.txt")

  #Website4:Whatismyip.com
    api_key = '0270ce5e12f1adff8f18a00d2d0a7164'
    url = f"https://api.whatismyip.com/ip-address-lookup.php?key={api_key}&input={i}"
    response = requests.get(url) 
    with open (file+"IP_search.txt",'ab') as f:
       f.write("Whatismyip:\n".encode("utf-8")+response.text.encode("utf-8"))
    f.close()
    end("IP_search.txt")

    if(pdf_con!="0"):
      pdf(file+"IP_search.txt",file+"IP_search.pdf")

    if(json_con!="0"):
      JSON(file+"IP_search.txt",file+"IP_search.json")

  #~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    '''Checking the domain name obtained from the investigation
       and try to get info of the domain using various OSINT tools
    '''
  elif(choice=="Domain name"):

    hint("Domain_search.txt")
  #Website1:IP2WHOIS
    url="https://api.ip2whois.com/v2?key=B14E1C337A4BA087E8005CC9E21068FD&domain="+i
    response=requests.get(url)
    write("Domain_search.txt",json.loads(response.text),"ab","IP2WHOIS:")
    end("Domain_search.txt")

  #Website2:WhoisFreaks
    url="https://api.whoisfreaks.com/v1.0/whois?apiKey=2179d3848cd546a7a2a9ece02f347472&whois=live&domainName="+i
    response=requests.get(url)
    write("Domain_search.txt",json.loads(response.text),"ab","WhoisFreaks:")
    end("Domain_search.txt")

  #Website3:Virustotal
    url=f"https://www.virustotal.com/api/v3/domains/{i}"
    headers={'x-apikey':'74103328471597f0a659056c7db646b919809c3e57231b7e2a04a8b339966a5b'}
    response=requests.get(url,headers=headers)
    #/
    print("Virustotal:",response.json()['data']['attributes']['last_analysis_results']['CMC Threat Intelligence']['category'])
    #/
    text3_1=json.loads(response.text)['data']['attributes']['popularity_ranks']
    text3_2=json.loads(response.text)['data']['attributes']['last_analysis_results']
    write("Domain_search.txt",text3_1,"ab","VirusTotal:")
    write("Domain_search.txt",text3_2,"ab")
    end("Domain_search.txt")
    
  #Website4:Domainsdb
    url="https://api.domainsdb.info/v1/domains/search?domain="+i
    response=requests.get(url)
    write("Domain_search.txt",response.json(),'ab',"Domainsdb")
    end("Domain_search.txt")

    if(pdf_con!="0"): 
      pdf(file+"Domain_search.txt",file+"Domain_search.pdf")
      
    if(json_con!="0"): 
      JSON(file+"Domain_search.txt",file+"Domain_search.json")
    
  elif(choice=="Hash"):

    hint("Hash_search.txt")
    if(os.path.exists(i)):
    #Find hash
      url = "https://www.virustotal.com/api/v3/files"
      files = { "file": (rf"{i}", open(rf"{i}", "rb")) }
      headers = {"x-apikey": "74103328471597f0a659056c7db646b919809c3e57231b7e2a04a8b339966a5b"}
      response = requests.post(url, files=files, headers=headers)
      url=json.loads(response.text)['data']['links']['self']
      response=requests.get(url,headers=headers)
      i=response.json()["meta"]["file_info"]["md5"]
      print("MD5:",i)
    #Website1:VirusTotal
    url = f"https://www.virustotal.com/api/v3/files/{i}"
    headers = {"accept": "application/json","x-apikey": "74103328471597f0a659056c7db646b919809c3e57231b7e2a04a8b339966a5b"}
    response = requests.get(url, headers=headers)
    detected_undetected=[]
    for k in response.json()['data']['attributes']['last_analysis_results'].values():
        detected_undetected.append(k['category'])
    #/
    print('Virustotal: Not Malicious' if detected_undetected.count('undetected')>detected_undetected.count('detected') else 'Virustotal: Malicious')
    #/
    write("Hash_search.txt",response.json()['data'],'ab',"Virus total")
    end("Hash_search.txt")
    
    #Website2:MetaDefender
    url = "https://api.metadefender.com/v5/threat-intel/av-file-reputation/"+i
    headers = {"apikey": "59f5f4537b3982f64cc7c0506dffb054"}
    response = requests.get(url, headers=headers)
    write("Hash_search.txt",response.json(),'ab',"Meta defender")
    end("Hash_search.txt")

    if(pdf_con!="0"): 
      pdf(file+"Hash_search.txt",file+"Hash_search.pdf")
      
    if(json_con!="0"): 
      JSON(file+"Hash_search.txt",file+"Hash_search.json")

except ImportError:
  print("ImportError")