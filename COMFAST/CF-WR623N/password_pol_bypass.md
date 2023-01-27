#### CVE-2022-47699
#### Product: CF-WR623N (http://www.comfast.com.cn/index.php?m=content&c=index&a=show&catid=98&id=13)
#### Firmware version: V2.3.0.1 
#### Driver version: 4.1.0.0_CL15074 
#### Vendor Fix: N/A
#### Root Cause: Improper Clientside input checks resaulting in password policy bypass

--------

I realize that this is somewhat of a lame best practice vulnerability aimed at improving the overall security posture of the application and the users.               
The application is not following its own security best practices. I understand that if somebody goes out of their way to put a shitty password, its really their fault but your policies should be applied consistently across the board to better improve the security posture of the application. 
As seen below the frontend forces a 5-32 password             

![image](https://user-images.githubusercontent.com/25066959/207156643-5444116a-0e4b-45a8-b0a8-752eaa8c5751.png)

Below we're going to be setting the password or the admin user to the single character `k`     

![image](https://user-images.githubusercontent.com/25066959/207156671-0c23f7e9-c58a-4f59-8f3f-6a9ac6e63935.png)

The password changed worked because we're not able to auth as the admin user with the password `k`      
![image](https://user-images.githubusercontent.com/25066959/207156690-f84ed5db-7884-4bd8-845a-48fe2ef03a40.png)
