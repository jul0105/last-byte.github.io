---
published: true
image: /img/cybersoldier.PNG
title: Tactical Debriefing I - Offshore
subtitle: Lessons learned by pwning the Offshore pro lab by HTB
---
Greeting everyone, last is back! So, on the 28th of September I played the [RomHack](https://romhack.io) CTF with my fellow mates from [JBZ](https://jbz.team/) and we got third, thanks to a flag submitted at the last second (a typical CTF tactic to make the other teams relax and then pwn them at the very last moment [;)](https://xkcd.com/541/). The prize for our ~~awkward~~ outstanding performance was a set of coupons for HTB's pro labs, either Rasta Labs or Offshore. I chose to go with Offshore, as I had seen from reviews that it was more realistic and less CTF-like than Rastamouse's one. This post is going to cover what I learned in the process from a "tactical" perspective, I won't write any spoilers about the lab itself because that would be unfair to others who are still inside it (and against HTB's rules, I think).  
  

## Table of contents
Here's a overview of what I'm going to cover in this post:
 - Introduction and lab description
 - Choosing and setting up a C2 Framework
 - Covenant usage
 - Pivoting techniques
 - SSH tunneling done the right way
 - Bloodhound
 
## Introduction and lab description
The lab is made of 17 machines, 16 of which in scope (technically the firewall is not in scope, but they say noone is going to keep you from trying to pwn it so ¯\\\_(ツ)\_/¯). There are 29 flags in total (yes, 29, which is not a round number like 30. Yes, I contacted them to make sure there wasn't a hidden flag). Here's the list of the flags' tasks and machine names:
  
  
![offshoremachines]({{site.baseurl}}/img/offshoremachines.PNG)

I'm not going to disclose a lot of information about the topology of the internal network, but I can say there is a DMZ in which you can access a webserver located at an IP address in the 10.10.110.0/24 subnet. By compromising it you can then pivot inside the network
 