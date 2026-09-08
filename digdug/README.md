# Dig Dug Write-up | 报告

This is my write-up for the [Dig Dug](https://tryhackme.com/room/digdug) room. The goal is find the flag in DNS records, but it says that we have to work with `givemetheflag.com` domain, because "this only responds to a special type of request for a `givemetheflag.com` domain". Also, "turns out, this MACHINE_IP machine is also a DNS server!".

---

After getting MACHINE_IP, I searched for DNS records via `dig` command.

```
dig MACHINE_IP
```

As you can see we got some domains: `a.root-servers.net` & `nstld.verisign-grs.com`, but we don't have to focus on that, since the hint is about the DNS records.

After that I decided to look for open ports on MACHINE_IP, but it was a mistake and just a waste of time. I'll write some advices down here after the solving part.

A little later I understood that we need to combine MACHINE_IP with the domain `givemetheflag.com` using `dig`:

```
dig @MACHINE_IP givemetheflag.com
```
This command above lets us see what records specific DNS server sees about the domain.

And the TXT-record reveals the flag.

## Important advice

When I was solving the room, I was digging too much. I searched for open ports using Nmap, then I tried to access to SSH... I forgot about the main idea of the room, DNS enumeration. Please, always keep in your head the concept of the room, always remember only the info you really need, do not try to find something that you don't even need. Don't make my mistakes. It will save your time and energy.
