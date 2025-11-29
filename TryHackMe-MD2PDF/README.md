# TryHackMe MD2PDF Write-up
> I used the TryHackMе AttackBox for this room.
> https://tryhackme.com/room/md2pdf
## Overview
This is my write-up for the MD2PDF room. The goal was to exploit a web application that converts text to PDF to access a restricted page with flag. 
I divided it into three steps:

1. Reconnaissance (Scanning & Enumeration)
2. Exploitation (SSRF via PDF Generation)
3. Conclusion

### Reconnaissance (Scanning & Enumeration)

### Scanning

After getting target IP-address, we can scan it to search for open ports using Nmap.
```nmap (target-ip)```

<img width="1446" height="519" alt="изображение" src="https://github.com/user-attachments/assets/0c83633f-3fd2-4926-a841-8caedcd42ebf" />

As you can see, we got 3 open ports: 80 (web), 22 (ssh), 5000. Now we can check what services are running on these ports.
Type: http://(target-ip):80 in your browser to go to the site with 80 port.

<img width="485" height="73" alt="изображение" src="https://github.com/user-attachments/assets/942ae915-6fe3-4222-9871-67c70735bfd0" />

After going to this site, we see a form that gets a text, then after you press the "Convert to PDF" button, it redirects you to the site with PDF text page. 

<img width="1218" height="530" alt="изображение" src="https://github.com/user-attachments/assets/1cf41027-478c-45be-8f8e-39a7bc9025d7" />
<img width="1113" height="602" alt="изображение" src="https://github.com/user-attachments/assets/92c504df-75d5-4a0c-a186-7743aa78095d" />

Now let's check 5000 port: http://(target-ip):5000

<img width="500" height="242" alt="изображение" src="https://github.com/user-attachments/assets/c6da6576-8d43-429e-a40f-ac6d6edc60b5" />

This page is similiar to the previous one, but the "Convert to PDF" button was unresponsive.
What about 22? After http://(target-ip):22 we get an error, so we don't need it. I forgot to take a screenshoot.

### Enumeration

I used Gobuster to find hidden directories on the web server.
I ran the following command: 
```gobuster dir -u http://(target-ip) -w /usr/share/wordlists/dirbuster/directory-list-2.3-small.txt```
After the command we have an output:

<img width="724" height="411" alt="изображение" src="https://github.com/user-attachments/assets/4bee595f-26b6-43a8-a60e-a0356ed99aea" />

It says that there's 2 hidden drectories, "/admin" and "/convert". Now we can try to go to these pages.
```http://(target-ip)/admin```

<img width="480" height="188" alt="изображение" src="https://github.com/user-attachments/assets/74e785b4-6a94-49c5-bc10-8988d908f980" />

After going to the /admin page, it says that it is forbidden and can be seen only by localhost:5000 (port 5000). This is an important information. What about /convert?
```http://(target-ip)/convert```

<img width="504" height="182" alt="изображение" src="https://github.com/user-attachments/assets/eaeae537-20cd-4065-8676-5e20935d147a" />

We didn't get anything. So let's focus on that /admin page.

### Exploitation (Injection)

After the reconnaissance we have:
* Which ports are open (80, 22, 5000) by using nmap
* Hidden directories (/admin, /convert) by using gobuster
* The info that the /admin page can be only seen by localhost:5000

I injected an iframe pointing to the restricted page into the form:
```<iframe src= "http://127.0.0.1:5000/admin"></iframe>```

<img width="613" height="141" alt="изображение" src="https://github.com/user-attachments/assets/0438ea21-e191-4c42-81d6-fece099e52f9" />

Why "127.0.0.1"? Because we need to check the localhost, and "127.0.0.1" is always a local host's IP.
The PDF displayed the contents of the localhost:5000/admin page, revealing the flag.

### Conclusion

* Vulnerability: The main vulnerability was an SSRF in the PDF generation, by user input
* Impact: This allowed an attacker to access internal services (like on port 5000) and retrieve information (the flag)

*Notes:*
What's SSRF? (Server-side request forgery)
Server-side request forgery is a computer security vulnerability that enables an attacker to send requests from a vulnerable server to internal or external systems or the server itself.

