# VirusTotal-IP-powershell
Triage an IP using powershell

First you need an API key from virusTotal: https://www.virustotal.com

You need to make an account. Once you have done so you can click on the top right > API Key and your api key will available


![image]https://github.com/jkerai1/VirusTotal-IP-powershell/blob/a4e3518b66e3f7411d29f11d290f076944793d53/API%20key%202.PNG
Key is found:

![image]https://github.com/jkerai1/VirusTotal-IP-powershell/blob/a4e3518b66e3f7411d29f11d290f076944793d53/API%20key%202.PNG
Then you can paste your api key within the line (line 14 at the moment, however this may change)


$headers.Add("x-apikey", "YOUR KEY GOES HERE")

Now program is ready to use:

Paste in IP (I stands for IP): 

![image]https://github.com/jkerai1/VirusTotal-IP-powershell/blob/a4e3518b66e3f7411d29f11d290f076944793d53/1.png
