# VirusTotal-IP-powershell
Triage an IP using powershell

First you need an API key from virusTotal: https://www.virustotal.com

You need to make an account. Once you have done so you can click on the top right > API Key and your api key will available

![Api key 1PNG](https://user-images.githubusercontent.com/55988027/154651910-9bdc4c45-a140-45d8-89fc-36907ce0edb8.PNG)


Key is found:
![API key 2](https://user-images.githubusercontent.com/55988027/154651904-77291d0e-8d44-4767-a0df-047e96a1f530.PNG)

Then you can paste your api key within the line, between the quotation marks (near line 12-14 at the moment, however this may change)

![Capture](https://user-images.githubusercontent.com/55988027/154652083-f8914757-9ec9-457e-afa7-5790dcdfc2a1.PNG)

$headers.Add("x-apikey", "YOUR KEY GOES HERE")

Now program is ready to use:

Paste in IP (I stands for IP): 

![1](https://user-images.githubusercontent.com/55988027/154651931-e9d4a186-b305-4275-9a52-5b572e206b2b.png)


To do:

Set-Clipboard for final result?
