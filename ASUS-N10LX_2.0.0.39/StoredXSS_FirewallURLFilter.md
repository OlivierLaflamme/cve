CVE: Pending        
Version: 2.0.0.39        
MD5: 461ff9bc8d79962101e8be65f3a56ab6         
Firmware type Instr_set: MIPS       
Vendor: ASUS       
Router Model: RT-N10LX             
Description: Stored XSS in ASUS Firewall URL Filter Keyword parameter.        

This vulnerability was analyzed and discovered with the reverse engineering tool known as Shambles by Lian Security.

------

Your javascript code will in the URL Keyword list as seen below.      
![image](https://github.com/OlivierLaflamme/cve/assets/25066959/a1ca9a8a-703f-4d6d-98cc-6cb935a80fea)

We can test out the alert(1) and see that its interpreted and triggered.     
![image](https://github.com/OlivierLaflamme/cve/assets/25066959/45223030-0785-4db6-b304-d39c7ee6e441)

Below is our post request to the formFilter.     
![image](https://github.com/OlivierLaflamme/cve/assets/25066959/1cbf81bd-70c8-4866-8aa5-fcbc2bfac52e)

note on the client side there is a max input length of 30 which is specified in the urlfilter.asp as seen in the image below but this can be bypassed serverside.     
![image](https://github.com/OlivierLaflamme/cve/assets/25066959/18f8ab2a-207f-425e-9186-bb9ded51dd2f)

This XSS is the result of the urlFilterList function which gets called upon to handle the input provided from the formFilter function which initially receives the url value from the POST request. Think of the urlFilterList function as being responsible for how the data on the page is "formatted".               
![image](https://github.com/OlivierLaflamme/cve/assets/25066959/91dc3110-8ca2-4938-8b0a-b56a81220106)

We have to look at the function below to understand what is happening.      
![image](https://github.com/OlivierLaflamme/cve/assets/25066959/f5050aa2-1888-44ec-983d-0a54fe482d6d)

p1 is a variable of type FILE* which represents a file stream. It is passed as a parameter to the urlFilterList function. This is actually the url parameter of our POST request which is passed through urlFilterList from a function called formFilter. The fprintf statement in the code snippet is responsible for formatting and writing data to a stream, which in this case is represented by the p1 parameter.         

```
v1 += fprintf(p1, "<tr><td align=center width=\"30%%\" bgcolor=\"#C0C0C0\"><input type=\"checkbox\" name=\"select%d\" value=\"ON\"></td>\n<td align=center width=\"70%%\" bgcolor=\"#C0C0C0\">%s</td></tr>\n", v5, &var38);
```

The %s in the format string represents a string value, which is provided by the &var38 expression. The & operator is used to get the address of the var38 array, which is then interpreted as a string.     

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
