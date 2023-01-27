#### CVE-2022-47700
#### Product: CF-WR623N (http://www.comfast.com.cn/index.php?m=content&c=index&a=show&catid=98&id=13)
#### Firmware version: V2.3.0.1 
#### Driver version: 4.1.0.0_CL15074 
#### Vendor Fix: N/A
#### Impact: Unauthenticated Information Disclosure 
------

I'll preface this by saying that obviously you do need to be connected to the network to perform this attack. You can achieve this by plugging directly into the router. This is assuming you have physical access or have the owner of the device provide you with the PSK or connect you themselves. Then and only then can you interface with the device.            

As seen below, since we don't actually need to be authenticate or have a valid session we have more-or-less access to all the router features. Because of this we're able to retrieve the routers configuration and view the admin users password and see the PSK in clear text.           

![image](https://user-images.githubusercontent.com/25066959/207155772-a8282ba1-08ea-4ce6-86d9-6f948d4c205f.png)       
 
![image](https://user-images.githubusercontent.com/25066959/207155814-c773612e-229f-410a-95c4-85ab968bb9c9.png)       
