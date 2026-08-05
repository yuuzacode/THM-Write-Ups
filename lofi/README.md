# Lo-Fi Write-up | 报告

This is my write-up for the [Lo-Fi](https://tryhackme.com/room/lofi) room. This is CTF challenge focused on filesystem traversal.

After getting an IP address of the machine, we can go to the web page `http://MACHINE_IP`:

This room is about filesystem, so I enumerated directories using FFuF tool:
```
ffuf -u http://MACHINE_IP/FUZZ -w /usr/share/wordlists/seclists/Discovery/Web-Content/DirBuster-2007_directory-list-2.3-medium.txt
```
(if you don't have this wordlist, download them by running `sudo apt install seclists`)

After enumeration we found the `server-status` directory, but we are not permitted to access it.

Then I checked web source and found directories with files, but there was no flag.

The web page contains a search bar. If you type something and press "Go!" button, it will change the URL of the page and execute the search.

We can use it. Think just like in your terminal: we're going to root of the filesystem by using several `../` commands and going to `/etc/passwd` directory. Also don't forget to change `?search=` in URL to `?page=`, so we can see it.

The result proves that we can access data by URL injection. Let's check for `flag.txt`.

The page reveals the flag.

## Conclusion

In this room, I learned how to:
* Use URL injection to access data.
