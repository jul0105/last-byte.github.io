---
published: true
image: /img/windows-logo-glitched.png
title: 21st Century Active Directory Attacks - Part 0
subtitle: The gathering storm...
---
  
  
You know folks, my life is kinda busy at the moment. Basically it's squeezed between my work, my [master's degree course in Cybersecurity](https://cybersecurity.uniroma1.it/) at the university, the [Advanced Web Attacks and Exploitation course](https://www.offensive-security.com/information-security-training/advanced-web-attack-and-exploitation/) by Offsec and the [Offshore labs](https://www.mrb3n.com/?p=551) on Hack The Box. Do you ever have those moments when you suddenly realize you are putting too much stuff in your life to ever make it work but you can't stop thinking "man, this thing is so cool, I should find a way to fit it in my schedule even though I literally don't have time to even sleep"? I have them all the time! And if it weren't for ~~the lack of~~ money, I would have bought a shitload of courses to keep myself occupied (like I have free time now, right? lol). 
  
  
![blog]({{site.baseurl}}/img/blog.JPG){: .center-block :}
  
  
So, what's the point in this introduction? Ever since I took the [Attacking and Defending Active Directory](https://www.pentesteracademy.com/activedirectorylab) course and lab by Pentester Academy (which, given the cost and the amount of information I learned, I highly recommend by the way) I was stuck with the idea of starting a post series on Active Directory from a offensive point of view. I thought it would be really useful (for me as a memento and for others to learn of course) to keep the things I learned in a tidy and coherent way. This thought sprang up again lately, when I pwnd the first domain of the Offshore labs, and I finally made up my mind about it. And of course it will be a problem, because days are (still) 24 hour long and noone has invented the [Hyperbolic Time Chamber](https://dragonball.fandom.com/wiki/Hyperbolic_Time_Chamber) yet.
<br>
<br>
Ok, enough with the stream of consciousness.  
<br>
<br>

## Topics covered

In this post series we are going to take a look at many aspects concerning Active Directory. We will start slow, from the basics and then move onto more complex topics like authentication mechanisms and attacks. With this in mind I want to cover the following topics:
- Basics of Active Directory: I'll explain what forests and domains are, how they interact with the environment, the protocols and the general behaviour of AD; 
- Active Directory reconaissance and enumeration. To do this we will use the famous Powerview module for Powershell;
- Kerberos, the ~~in~~famous authentication mechanism loved by Red Teamers and hated by Blue Teamers;
- AD attacks, focusing specifically on how to harness the power of Mimikatz in its various forms to perform attacks like overpass the hash, forging golden and silver tickets, dump credentials off DCs and machines;
- AD persistence and backdooring;
- Setting up a red teaming infrastructure with Covenant as a C2 framework and using redirectors to keep the C2 server "safe" from a tactical point of view.  
  
  
I'll try to keep all the explanations as offensive-oriented as possible. I want to stress out however that none of this is new, none of this is a product of my personal research, it's just the result of countless hours reading and practicing the techniques developed by other fellow hackers who did the heavy lifting way before me. Just to name a few: [harmj0y](https://www.harmj0y.net/blog/about/), [Nikhil Mittal](http://www.labofapenetrationtester.com/p/about-me.html), [Tim Medin](https://twitter.com/timmedin), all the folks from [Specter Ops](https://specterops.io/), [Sean Metcalf](https://adsecurity.org/?page_id=8), [Benjamin Delpy](https://twitter.com/gentilkiwi) and countless other security researchers around the globe. As Sir Isaac Newton once said:

> If I have seen further than others, it is by standing upon the shoulders of giants.
  
<br>

Enough for the part 0 intro now, let's dive right in.
<br>
<br>
<br>
<br>

## Oh Active Directory, Active Directory, wherefore art thou Active Directory?

So, Active Directory (from now on abbreviated AD) is a suite of technologies developed by Microsoft and is, at its core, a directory service employed by Windows domains to keep track of basically everything. It provides authentication mechanisms, objects management, users and groups management, security and configuration capabilities all centralized to a handful of servers, sometimes even just a single server. Practically it allows administrators to have centralized (when properly implemented) and secure (WHEN PROPERLY IMPLEMENTED) management of an entire network of devices.  
  
AD is hierarchically structured and its basic building blocks are:
 - Forests
 - Domains
 - Organizational Units (OU)  
   
A forest can be composed of one or more domains and inside a single domain you can find one or more OUs. Keep well in mind that forest are considered a security boundary, while __<u>domains are not considered a security boundary</u>__. If you are not already accostumed to AD and AD attacks, it's a phrase that might not make much sense to you as of now, but we will come back to it later. Suffice it to say that most of the times if an attacker manages to take full control over a domain in a forest, the entire forest is to be considered compromised. We will come back to it in later posts.
  
  
![blog]({{site.baseurl}}/img/blog.JPG){: .center-block :}
  
  
The keystone of AD is the Domain Controller (DC). The DC is the machine (usually a Windows Server) to which all the other machines and users authenticate and with which everything in a domain interacts, be it for requesting access to a service or checking if a user has permission on a certain object. Let's say for example that user Bob wants to access a resource hosted on Alice's server. To access the resource Bob first queries the DC, asking for access to said resource, and the DC provides him with information to access Alice's server and then redirects him to Alice's server. At this point Bob provides Alice's server with the information given to him by the DC and Alice's server decides wether he's allowed to access the resource or not. This is, oversimplified of course, how Kerberos authentication works. Kerberos is another key technology in Active Directory, but we will analyze it later. The key takeaway here is: DCs are fundamental. If the DC falls (both from an "architectural" and a hacking point of view) it takes everything down with it. Because of that, DCs are (or should be) the most protected and well defended piece of the AD architecture.
