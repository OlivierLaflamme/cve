#### CVE-2022-47701
#### Product:CF-WR623N (http://www.comfast.com.cn/index.php?m=content&c=index&a=show&catid=98&id=13)
#### Firmware version V2.3.0.1 
#### Driver version was 4.1.0.0_CL15074 
#### Vendor Fix: N/A
#### Root cause: Lack of input sanitization
--------

Affected Component: 

This one is fairly self explanatory, in the 3rd router setup step, you're allowed to configure the name of the SSID. Again, in the grand scheme of things, at the moment this is absolutely impact-less.         

However, if they do patch then maybe you could make an overblown not realistic attack scenario leveraging this.               

`<img src=x onerror=prompt(1)>` 

![image](https://user-images.githubusercontent.com/25066959/207156053-e2c09c2f-ed42-47cf-852b-ecd1fed3eb06.png)     

SSID can only be 32 characters long. If you're a web skid like me you might be using XSS Hunter however, as you know, these payloads weren’t going to work. So instead I just created a short domain that forwarded to my XSS Hunter payload page. As seen below, this worked like a charm.         
![image](https://user-images.githubusercontent.com/25066959/207156251-90c3be3c-3445-486b-869f-4d835d4f0bd9.png)        

If you don't want to purchase a short, and typically expensive domain you can simply use the following as POC's which I think are more than illustrate the point. If you want some out-of-the-box somewhat impact-less short XSS payloads this is a good resource.             
To illustrate this differently, I'll use tiny urls and if they get unpacked then it proves the vulnerability. In this case tiny.cc/1lnsuz is the minified URL that redirects to google.com. In theory, if I set my SSID to <embed src=//tiny.cc/1lnsuz which is 28 in length I should pop google.com.           

![image](https://user-images.githubusercontent.com/25066959/207156208-45f0928e-b7d2-4de4-878f-0a3b4bd031e5.png)       

Look what happens when I login to the router with this SSID.         

![image](https://user-images.githubusercontent.com/25066959/207156341-28a2e39f-42a8-433a-abf1-27bb6328ce0b.png)

 
It fetches the minified url which in turn gets google.com.         
