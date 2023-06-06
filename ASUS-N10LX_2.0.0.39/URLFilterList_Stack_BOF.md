CVE: Pending        
Version: 2.0.0.39        
MD5: 461ff9bc8d79962101e8be65f3a56ab6         
Firmware type Instr_set: MIPS       
Vendor: ASUS       
Router Model: RT-N10LX             
Description: Stack Buffer Overflow in in ASUS Firewall URL Filter parameter which causes the application to crash requiring a reboot this BOF behaves like a DOS.

This vulnerability was analyzed and discovered with the reverse engineering tool known as Shambles by Lian Security.

------
Shambles identified an overflow at an offset in the formFilter function.      

![image](https://github.com/OlivierLaflamme/cve/assets/25066959/5396c4b1-2a39-4c53-8b50-c4aafb888588)

This is actually a humongous function, after a little bit of looking around our previous XSS was the result of an addFilterUrl operation.    
![image](https://github.com/OlivierLaflamme/cve/assets/25066959/674a5cb8-d526-4537-8887-9a680d3b8409)

There is nothing really important going on here but we get insight that v10 is assigned the value returned by the get_cgi("addFilterUrl") function which is going to be Apply. The snippet below is what we care about.        

![image](https://github.com/OlivierLaflamme/cve/assets/25066959/3012c5ad-e3b9-404c-941e-8afcc345600c)

In this code, the if statement checks the value at the memory address stored in var34. It casts var34 to a byte pointer ((byte *)var34) and dereferences it (*(byte *)var34). If the value is not zero, the following operations are executed:
1. v64 is assigned the value returned by the get_cgi("url") function.        
2. v65 is assigned the value of v64.     
3. If v64 is equal to zero, indicating a null value, v65 is reassigned to the memory address of byte_4699f0.           
4. The strcpy function is called to copy the content of v65 to the destination buffer vara0.        

The surrounding code and the definition and usage of vara0 to my understanding is what is getting called in the urlFilterList function which does not have sufficient memory allocated for the destination buffer. Therefore, we have the ability to leverage v65 the url parameter to exceed the buffer's capacity.          

![image](https://github.com/OlivierLaflamme/cve/assets/25066959/83d1af6f-f4e2-459a-b1dc-2e83cac26527)
In the given function, the variable var38 is defined as a character array of size 32 (char var38[32]). Which is our url parameter also known as v65. This means it can store a maximum of 32 characters.     

The function utilizes fprintf to write data into the output stream p1. However, there seems to be a potential issue at line 28.        
![image](https://github.com/OlivierLaflamme/cve/assets/25066959/9b34f2ba-dd72-4778-b299-20db97c856ec)

At this line fprintf is used to format a string and write it to the output stream. The second format specifier %s expects a null-terminated string as the corresponding argument.           

However, the &var38 is used, which is a pointer to the character array var38. If the content of var38 is not null-terminated or exceeds the allocated size of 32 characters, it could lead to a buffer overflow vulnerability. To test this we will use a large value for the &url parameter as seen below.          
![image](https://github.com/OlivierLaflamme/cve/assets/25066959/956967fc-e245-4017-a682-d837a9acacec)

Once this request is sent to the router the application segfaults and we cause a crash as seen below.        
![image](https://github.com/OlivierLaflamme/cve/assets/25066959/26a66452-b716-455c-bcf3-9f3ef87a6cac)

The image below shows the httpd binary supporting the web application crashing.            
![image](https://github.com/OlivierLaflamme/cve/assets/25066959/9493999a-ace5-4b39-a9a3-b96366423e41)



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
