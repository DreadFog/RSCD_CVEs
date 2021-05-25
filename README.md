# RSCD_CVEs
My research and works about the CVE 2016-5063/1542/1543 about the RSCD agent


You will find two different files in this repo:

- one that was adapted from @bao7uo, as its script was for python 2 and the formatting was not working anymore for python 3. It allows the attacker to Get some intel about the host OS and a listing of the users of the server.
This vulnerability works up until the version 8.6 patch 1.

- A second script that allows Remote Code Execution on the server through the vulnerabilities listed above.
I was able to curl a file and execute it without any problem. I guess you can do pretty much anything from this.
