CVE: CVE-2023-34942     
Version: 2.0.0.39        
MD5: 461ff9bc8d79962101e8be65f3a56ab6         
Firmware type Instr_set: MIPS       
Vendor: ASUS       
Router Model: RT-N10LX             
Description: Stack Buffer Overflow in in ASUS Wireless Mac Address mac parameter which causes the application to crash requiring a reboot this BOF behaves like a DOS.

This vulnerability was analyzed and discovered with the reverse engineering tool known as Shambles by Lian Security.

------
Shambles identified an overflow at an offset in the formFilter function.      

![image](https://github.com/OlivierLaflamme/cve/assets/25066959/693d4b82-b7f3-44f0-a3e0-6efa113398bf)

The vulnerable portal is the one seen below.      
![image](https://github.com/OlivierLaflamme/cve/assets/25066959/130b0854-b9c2-4d4a-bc54-c469e7cd77e4)

Proper usage of the portal would resault in the following httpd function output so our function managing the opperation is `formWLAc`.      
![image](https://github.com/OlivierLaflamme/cve/assets/25066959/9fbc3e2e-fcf7-4816-9d70-7b5bcbcb6f94)

Line 648-711 of the formFilter function appears to be a section of code that involves checking and processing a MAC address. Let's break down the code and analyze it step by step.        
![image](https://github.com/OlivierLaflamme/cve/assets/25066959/345213d2-f6f6-4831-bd89-c115bbfa1e07)

In the code below, the get_cgi function is called with the argument mac. The result is stored in v55, and then assigned to v56. 
![image](https://github.com/OlivierLaflamme/cve/assets/25066959/8c95254d-a230-4747-b491-79359b79308b)

If we have no input then we error out since the code checks if v56 == 0. 
![image](https://github.com/OlivierLaflamme/cve/assets/25066959/3478008a-6967-4186-9517-8b4b91484b58)

This section calculates the length of the v56 string and stores it in v76. If the length is 12 which should be the size of the provided mac parameter aka the mac address, it enters a loop. Within the loop, it processes the v56 string two characters at a time. The first character is stored in v98, and the second character is stored in v99. Various operations and function calls are performed on these characters. The loop continues until a condition is met or the loop reaches its end.         
![image](https://github.com/OlivierLaflamme/cve/assets/25066959/6f28cf05-8137-46d2-9067-496898e7ce19)

Now it doesn't actually matter if we enter this loop where if (v76 == 12) gets checked. Because it's my understanding that no matter what happens the parameter gets passed through to macFilterList 
![image](https://github.com/OlivierLaflamme/cve/assets/25066959/879842d0-93c0-4d6f-bd67-8cff86467edf)

The provided code appears to be a function named macFilterList that takes four integer parameters (p0, p1, p2, p3) and returns an integer value.       
You have your definition bellow:       
1. varc4, varc0, varbc, varb8: These variables are integers and used for storing values retrieved from memory.       
2. vara8, vara7: These variables are characters and used for temporary storage.          
3. var88: This is an array of characters with a size of 104, used for storing a formatted string.         
4. var20: This is an integer variable used to store a value obtained from apmib_get.          
5. v0, v8: These variables are of type FILE* and will be used as file pointers.          

after checking the results of apmib_get and iterating through a loop the code does the following:       
1. The code checks if *p3 (presumably a pointer to a string) is equal to the string "NetworkMap" using strcmp.        
2. If the comparison is true (i.e., they are equal), the code assigns the format string "[\"%s\"]" to v11 and &var88 to v10.       
3. If the comparison is false, the code assigns the format string ",[\"%s\"]" to v11 and &var88 (which is our mac addresss) to v10.   
4. It then uses fprintf to write the formatted string to the file pointer v8 (either v0 or p1).          

Below will be our POST body request. the `mac` field will be stuffed with `C`          

![image](https://github.com/OlivierLaflamme/cve/assets/25066959/71a83a3c-01b1-4958-9721-794cef7aaf61)

Below is the stack trace out httpd pid crashed and the application is DOS'd with no way of gracefully restarting.      
![image](https://github.com/OlivierLaflamme/cve/assets/25066959/2c8faaa0-034f-425c-808d-6dcbe8fa2afe)

Below is the httpd segfault verbose message.        
![image](https://github.com/OlivierLaflamme/cve/assets/25066959/d5bf24ba-c9a0-422a-8011-20aff1e8cbef)




Reported Issues To ASUS, product is EOL so will file for CVE's and stop looking into this router. 
```
Thank you for contacting ASUS and brining these to our attention.
We are sorry that RT-N10LX was end of life so there will be no firmware maintenance and no beta fix for this model.
We’ve also confirmed those issues do not impact our non-end of life models.


Let us know if any questions.
Thank you. 

Best regards,
ASUS PSIRT. ASUSTeK Computer Inc.
```
