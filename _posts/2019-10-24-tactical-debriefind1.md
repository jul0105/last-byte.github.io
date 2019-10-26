---
published: true
image: /img/cybersoldier.PNG
title: Tactical Debriefing I - Offshore
subtitle: Lessons learned by pwning the Offshore pro lab by HTB
---
Greetings everyone, last is back! So, on the 28th of September I played the [RomHack](https://romhack.io) CTF with my fellow mates from [JBZ](https://jbz.team/) and we arrived third, thanks to a flag submitted at the last second (a typical CTF tactic to make the other teams relax and then pwn them at the very last moment [;)](https://xkcd.com/541/). The prize for our ~~awkward~~ outstanding performance was a set of coupons for HTB's pro labs, either Rasta Labs or Offshore. I chose to go with Offshore, as I had read online reviews saying it is more realistic and less CTF-like than Rastamouse's one. This post is going to cover what I learned in the process from a "tactical" perspective, I won't write any spoilers about the lab itself because that would be unfair to others who are still going through it (and against HTB's rules, I think).
<br>
<br>
## Table of contents
Here's a overview of what I'm going to cover in this post:
 - Introduction and lab description
 - Choosing and setting up a C2 Framework
 - Covenant usage
 - Pivoting techniques
 - SSH tunneling done the right way
 - Bloodhound
<br>
<br>
## Introduction and lab description
The lab is made of 17 machines, 16 of which in scope (technically the firewall is not in scope, but they say noone is going to keep you from trying to pwn it so, ¯\\\_(ツ)\_/¯). While Windows is the preferential host (as you can see from the screenshot right below this paragraph) you will also find a few Linux machines. There are 29 flags in total (yes, 29, which is not a round number. Yes, I contacted them to make sure there wasn't a extra hidden flag). Here's a list taken from HTB's website containing all of the flags' tasks and machine names:
  
  
![offshoremachines]({{site.baseurl}}/img/offshoremachines.PNG)

I'm not going to disclose a lot of information about the topology of the internal network, but I can say that there is more than one subnet and that firewalls between subnets limit a lot your freedom of movement, even with reverse shells. Suffice it to say that at some point I was daisy chaining 4 remote desktop instances. Facing the "frontline" is a DMZ from which you can access a webserver located at an IP address in the 10.10.110.0/24 subnet. By compromising it you can then pivot behind the firewall and inside the network. From there it only gets tougher. 
  
  
One of the things I found really valuable about this lab is that, contrary to the OSCP's one for example, it's basically all about Windows Server 2016 and Windows 10, with some Windows 7 machines here and there. This kind of configuration forces you to use misconfigurations and develop a methodical approach to exploitation and privilege escalation as there is almost no room for kernel exploits, except from only one or two machines in the entire lab. This means that basically all you have to do to complete the lab is technical skills in Active Directory attacks. Keep in mind there is more than one forest. And in a forest there may be more than one domain.
  
  
There are also a few sidequests here and there, mainly about reverse engineering, web exploitation and cryptography. Having played in CTFs before helped a lot as these challenges were very CTF-like. The crypto one kept me busy for __<u>three days</u>__ as I usually don't even look at crypto challenges in CTFs (contrary to my fine mate [TheZer0](https://twitter.com/Th3Zer0) who should definitely [update his bio](https://twitter.com/last0x00/status/1187450723069583360)), but in the end I learned a ton about ECDSA and ElGamal encryption algorithm.
<br>
<br>
## Choosing and setting up a C2 Framework
Now that I've laid down the environment I want to tell you what was the process I went through to decide if and which Command and Control (C2) Framework to use for the operation and why I chose [Covenant](https://github.com/cobbr/Covenant) in the end. I want to stress out it was the first time using a C2 Framework for me as I've always done those kind of activities relying on "manual" tools like netcat and nmap, documenting and categorizing data with ~~im~~practical text files. While this simple toolbox has given me a very methodical approach to operations and has forced me to adapt and not rely on stuff like metasploit (which makes you very lazy), it isn't professional. Furthermore, when the amount of data started to grow (and it usually happened pretty fast) I regularly struggled to find old pieces of information scattered through the different .txt files. This, coupled with my need to not have my command and control tied to a single laptop, pushed me to evaluate what the infosec community had to offer when it comes to free and open source C2 Frameworks.

But first, the hell's a C2 framework? At its core it's a combination of server and client software designed to help with post exploitation tasks, data organization and team cooperation. C2 frameworks usually pack all the necessary components to setup a basic red team infrastructure like a C2 server (which is the keystone of the infrastructure) and a implant, which is the client software that's going to connect back to the C2 server and execute commands sent by the operator through the C2 server itself.

![C2 structure]({{site.baseurl}}/img/c2structure.jpg)

There is a multitude of C2 framework around, but before choosing it I jotted down a list of requirements that my ideal framework should have:
- Web UI: the server must be accessible and manageable through a web browser;
- Windows implants: given the prevalence of Windows machines in the lab the implant must be Windows compatible;
- Powershell integration: I did not want to fight with uploading PS script to target machines so the implants must be executable directly with a PS one-liner;
- Built-in red teaming toolkit: for the same reason of the powershell integration requirement, I wanted the implants to already have support for the important tools of trade, like Mimikatz, Rubeus etc.;

Having also implant pivoting and automatic intelligence management would have been a plus, so with these requirements at hand I started looking around and testing various C2 frameworks. After a few days tinkering and trying out different platforms I decided to opt for [Covenant](https://github.com/cobbr/Covenant). 

![covenant]({{site.baseurl}}/img/covenant.PNG)
  
  
What pushed me towards Covenant is that it ticked all my requirements. It's got a slick Web UI which is really well designed, with only a few bugs (which [cobbr](https://cobbr.io/about/) and the other devs usually fix promptly once a issue has been opened). The server runs on .Net and is cross platform, mine runs on Ubuntu server for example. Installing and running it is as simple as `dotnet build && dotnet run` but there's also a docker container if you don't want to get your hands dirty. 
  
  
![covenant2]({{site.baseurl}}/img/covenant2.PNG)

  
Through Covenant's web interface 

