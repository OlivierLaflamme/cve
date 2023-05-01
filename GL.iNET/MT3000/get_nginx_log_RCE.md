
CVE: CVE-2023-29778           
Version: 4.1.0           
Firmware type: Release2           
Compile time: 2022-11-03 9:47:27 (UTC+8:00)         
Vendor: GL.iNET           
Router Model: MT3000                
Description: Command Injection in "logread" RPC Requests, the injection can occur when the `get_nginx_log` type is called            

-------

<img width="655" alt="image" src="https://user-images.githubusercontent.com/25066959/219052736-0945c6aa-2978-4e6f-b97c-a48540bf08a3.png">


The following OS Command Injections vulnerabilities stem from the vulnerable code in `/usr/lib/oui-httpd/rpc/logread`. The injection can occur when the `get_nginx_log` type is called.             

![image](https://user-images.githubusercontent.com/25066959/219052390-d78940da-f6cb-4d52-bd31-cd00eaf4849d.png)

To perform a command injection through the parameter `%s` which is where the input for the `type` value is passed, an attacker would need to supply crafted values that are executed by a Linux binary. As seen below the `;` delimiter character is used followed by the cat binary to output the contents of the `/etc/passwd` file as seen below.             

![image](https://user-images.githubusercontent.com/25066959/219052599-5def0344-db28-40b9-a56d-1d8aa41bab9e.png)

