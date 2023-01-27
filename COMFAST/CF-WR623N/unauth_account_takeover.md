#### CVE-2022-47697
#### Product: CF-WR623N (http://www.comfast.com.cn/index.php?m=content&c=index&a=show&catid=98&id=13)
#### Vendor: COMFAST (Shenzhen Sihai Zhonglian Network Technology Co., Ltd)
#### Firmware version: V2.3.0.1 
#### Driver version: 4.1.0.0_CL15074 
#### Vendor Fix: N/A
#### Impact: Unauth password change of root user account
#### Description: an unauthenticated user has the ability to reset the password of the admin user account
-------

this endpoint can be accessed unauthed after a password has been set for the admin account/the device is initiated and running.       

![image](https://user-images.githubusercontent.com/25066959/207155872-1a0f6741-6edf-4657-9d28-87ba9ec274f0.png)

![image](https://user-images.githubusercontent.com/25066959/207155887-fd2a4161-749a-4983-8ae1-f38dd845d6a8.png)

This will cause the device to reboot as you're forcing a change in the configuration 

![image](https://user-images.githubusercontent.com/25066959/207155921-35baa7b9-c20e-46f2-ae7c-a618ac52132f.png)
