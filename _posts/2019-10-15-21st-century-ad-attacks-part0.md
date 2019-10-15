---
published: true
image: /img/windows-logo-glitched.png
title: 21st Century Active Directory Attacks - Part 0
subtitle: The gathering storm...
---
You know folks, my life is kinda busy at the moment. Basically it's squeezed between my work, my [master's degree course in Cybersecurity](https://cybersecurity.uniroma1.it/) at the university, the [Advanced Web Attacks and Exploitation course](https://www.offensive-security.com/information-security-training/advanced-web-attack-and-exploitation/) by Offsec and the [Offshore labs](https://www.mrb3n.com/?p=551) on Hack The Box. Do you ever have those moments when you suddenly realize you are putting too much stuff in your life to ever make it work but you can't stop thinking "man, this thing is so cool, I should find a way to fit it in my schedule even though I literally don't have time to even sleep"? I have them all the time! And if it weren't for ~~the lack of~~ money, I would have bought a shitload of courses to keep myself occupied (like I have free time now, right? lol).  
![blog]({{site.baseurl}}/img/blog.JPG)
  
  
So, what's the point in this introduction? Ever since I took the [Attacking and Defending Active Directory](https://www.pentesteracademy.com/activedirectorylab) course and lab by Pentester Academy (which, given the cost and the amount of information I learned, I highly recommend by the way) I was stuck with the idea of starting a post series on Active Directory from a offensive point of view. I thought it would be really useful (for me as a memento and for others to learn of course) to keep the things I learned in a tidy and coherent way. This thought sprang up again lately, when I pwnd the first domain of the Offshore labs, and I finally made up my mind about it. And of course it will be a problem, because days are (still) 24 hour long and noone has invented the [Hyperbolic Time Chamber](https://dragonball.fandom.com/wiki/Hyperbolic_Time_Chamber) yet.
<br>
<br>
Ok, enough with the stream of consciousness.

## Topics covered

In this post series we are going to take a look at many aspects concerning Active Directory. We will start slow, detailing what AD is, is not and how it works. I'll explain how domain trusts work and how to exploit them at your advantage. We will then have a look at Kerberos, the ~~in~~famous authentication mechanism loved by Red Teamers and hated by Blue Teamers. After detailing the basics we will go through all the most known attacks like Kerberoasting, forging golden and silver tickets, backdooring AD and implanting persistence measures on a compromised domain controller. I'll try to keep all the explanations as offensive-oriented as possible. I'll try to cover the use of [Covenant](https://github.com/cobbr/Covenant) as well to perform Red Team operations. I want to stress out however that none of this is new, none of this is a product of my personal research, it's just the result of countless hours reading and practicing the techniques developed by other fellow hackers. As Sir Isaac Newton once said:

> f I have seen further than others, it is by standing upon the shoulders of giants.
