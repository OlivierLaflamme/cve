
CVE-2022-47698

The adv_filters_url.htm endpoint is the target of this vulnerability. This endpoint is used to add URL filters to the router. In which the variable SET0 is the location in and we're injecting into which handles the entry of the filter within a table. In our case we want to inject into the second field which is going to be UF2 which maps to 0x0a070202 which in tern is 168231426.          

![image](https://user-images.githubusercontent.com/25066959/207156439-7b744888-a5c0-4c93-bc6a-7f26c1db9b38.png)

Therefore our command will be CMD=FILTER&GO=home.htm&SET0=168231427=1;0;<INJECTION>. When I test in Firefox I personally prefer using Firefox specific payloads such as <marquee onstart=alert(1)> for testing.             
  
![image](https://user-images.githubusercontent.com/25066959/207156518-2c0e1df6-d4cf-4532-9d82-2f93c122b57b.png)

  Once the POST request above is submitted, going to Advanced Users > URL Filtering will trigger the alert. Once again. this is fairly useless & impact-less given our situation, and lack of required authentication.         
  
  ![image](https://user-images.githubusercontent.com/25066959/207156548-02ad3927-f86c-4292-898a-5e4da222168f.png)

  
I don't blog a lot so ill share my favorite payload which leverages the movie / video content tags which are never ever filtered.          
  
  The payload can be seen below.
  ```<video controls oncanplay="alert()"><source src="http://mirrors.standaloneinstaller.com/video-sample/lion-sample.mp4"></video>```       

Once the page is refreshed we'll have the audio and video of  lion-sample.mp4 within the page.          
  
  ![image](https://user-images.githubusercontent.com/25066959/207156582-a7451836-472f-43d0-b3d5-50b70b45dcba.png)
