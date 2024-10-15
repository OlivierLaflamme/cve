CVE:        
Product: Mt300v2 (http://www.totolink.cn/home/menu/detail.html?menu_listtpl=download&id=55&ids=36)         
Vendor: TOTOLINK (Zioncom (Hong Kong) Technology Limited)       
Firmware version: 4.0.3c.7484        
Vendor Fix: N/A         
Impact: Unauth password change of root user account           
Description: an unauthenticated user has the ability to run arbitrary commands on the endpoint.               

----------


![image](https://github.com/user-attachments/assets/5f517659-649e-40e9-92ae-ff6f4d1c5a7f)


upgrade.so handles the function setUpgradeFW      

![image](https://github.com/user-attachments/assets/b9a0f56f-ecc8-4a52-96c4-b649a580d9be)

![image](https://github.com/user-attachments/assets/46ca445e-f68f-472d-a5ea-e373e46314ef)

![image](https://github.com/user-attachments/assets/7d6fff8a-fbc4-4ab0-879e-f9a5a977ca5d)


This code is vulnerable to command injection. The vulnerability is due to the fact that the websGetVar function used to obtain the value of the FileName variable from the web page gets passed to fopen. However, the value obtained from the web page is not properly validated or sanitized before being passed to the fopen. An attacker could potentially inject malicious commands into the "FileName" variable, which would then be executed by the "fopen" function. This could lead to the attacker gaining unauthorized access to the system, or executing arbitrary code on the target system. Additionally, there are calls to the "system" function which could also be used to execute arbitrary command injection.         

![image](https://github.com/user-attachments/assets/5c99b26b-7a3b-4405-90fc-fa5306b36dc7)

The code appears to be vulnerable to a content length bypass vulnerability. The vulnerability is due to the fact that the ContentLength variable is obtained from the web page using the "websGetVar" function, and then passed to the "strtol" function to convert it to a long integer. However, the value obtained from the web page is not properly validated or sanitized before being passed to the "strtol" function. An attacker could potentially set the value of the "ContentLength" variable to a very large number, which could cause a buffer overflow or other types of memory corruption, leading to arbitrary code execution or other types of attacks. Additionally, the check that is being made to ensure that the ContentLength is above 1000 (if (v3 < 1000)) is not sufficient, since an attacker could still provide a file larger than the flash size of the device (if (v3 < getFlashSize() << 20) ). It is recommended to validate and sanitize the value obtained from the web page and also to compare the "ContentLength" value with the maximum size of the flash before proceeding with the fopen function.                  

![image](https://github.com/user-attachments/assets/f74df859-0cd9-43bb-ba94-38d166e86c55)

The vulnerability is due to the fact that the "v2" variable, which is obtained from the web page using the "websGetVar" function, is passed to the "sprintf" function without proper validation or sanitization. An attacker could potentially inject malicious commands into the "v2" variable, which would then be executed by the "sprintf" function. This specific command sprintf(&var100, dword_16034 + "rm -rf %s 1>/dev/null 2>&1", v2); is using the rm -rf command that could be dangerous since it could be used to delete any file or folder without any confirmation. It is recommended to validate and sanitize the value obtained from the web page before passing it to the sprintf function.

![image](https://github.com/user-attachments/assets/6cccda7c-2e0f-48de-baea-d183656cffd1)

![image](https://github.com/user-attachments/assets/c9020e61-8d63-49b4-90f2-49ed293e5b33)
