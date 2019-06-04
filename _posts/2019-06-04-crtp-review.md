---
published: true
image: /img/defense2.png
title: Attacking and Defending Active Directory course review
subtitle: Active Directory attacks, from zero to hero
---
# Attacking and Defending Active Directory Course Review

![crtp]({{site.baseurl}}/img/activedirectorylab.png)

## Introduction
It's been almost two weeks since I took and passed the exam of the [Attacking and Defending Active Directory](https://www.pentesteracademy.com/activedirectorylab) course by Pentester Academy and I finally feel like doing a review. I was very excited to do this course as I didn't have a lot of experience with Active Directory and given also its low price tag of $250 with one month access to the lab I decided to give it a shot.

## The course material
The instructor is [Nikhil Mittal](https://www.linkedin.com/in/mittalnikhil/) who is a really good instructor, having reached at both DEFCON and Black Hat conferences. In my opinion the course is really well made and covers the basics of both Active Directory and Powershell. Of course a little bit of basic knowledge about what Active Directory is and what it is for is needed, but it's nothing that can't be gained with a week of good study. The course itself is a series of recorded lessons, 37 total, ranging between 6 minutes and 52 minutes, averaging 20 minutes each. Along with the lessons you'll receive the slides used by the instructor in PDF format and a connection pack to connect to the lab, which I'll discuss later. 

## The training
On the offensive side, the lessons cover domain and forest enumeration, local privilege escalation techniques, lateral movement and domain privilege escalation, domain persistence, and cross forest attacks. After the offensive part there's a defensive one, which covers countermeasures to the attacks taught in the previous lessons and how to harden your Active Directory environment and deploy detection systems. Every lesson assigns some tasks and learning objectives to complete before continuing to the next one. The walkthroughs of these learning objectives are covered by the videos from the 26 to the 36.

## The lab
What really shines in this course to me is the lab. Sure, the material given is great and well taught but knowledge without experience is only half the battle in my opinion. All of the learning objectives are done in the lab and you need to apply the techniques learnt through the course to finish them. The lab is a complete Active Directory environment, with state of the art, fully patched Windows Server 2016 and SQL Server 2017 machines. The environment is the moneycorp.local forest and the student starts from a machine in the child domain dollarcorp.moneycorp.local. From there he has to fully compromise his machine and gain SYSTEM privileges on it. Then he can start making his way through the domain, compromising accounts with higher privileges and escalating his way to the domain controller. After that he will need to apply persistence techniques such as Golden Tickets, Silver Tickets, Skeleton keys and so on. From there he will then have to perform cross domain attacks and escalate his privileges to the forest root and basically go god mode in the forest domain controller. Done that he will have to perform cross forest attacks and escalate his privileges into another forest. The lab is resetted everyday, except for the student machine, so that the environment is always clean and tidy. There are multiple purchase options, ranging from 30 days at $249 to 90 days at $549, but I feel that if you dedicate enough time one month is sufficient to complete the course and the lab.

## The exam
I can't say many things about the exam as you can imagine. I can only say that it's OSCP-like for what concerns the amount of time given, the environment somewhat resembles the lab one, and it's not easy. But I would say that all of the techniques needed to pass it are covered in the course, so if you truly learn the material and don't just memorize it you "should" be fine. The greatest satisfaction however is seeing all the critical accounts and systems fall one by one after your shots until your privileges are top. To quote Mr Robot:

> This, the thrill of pwning a system, this is the greatest rush. God access. The feeling never gets old.

After the ~~funny~~ technical part however you have to write a professional report describing all the steps that lead you to where you arrived. I ended up writing a 30 page report, give or take. You should also suggest mitigations and countermeasures, but having pwned everything I didn't bother doing it. Don't follow my bad example please :)  

By passing the exam you obtain your Certified Red Team Professional certification. Though the title sounds pretty cool, I don't feel like a professional, yet. There's still a ton of work and study I have to go through, but this course surely helped a lot and it was an amazing experience.
  
  
![certificate](https://api.accredible.com/v1/frontend/credential_website_embed_image/certificate/13051381)
