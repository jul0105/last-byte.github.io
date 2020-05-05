---
layout: post
published: false
image: /img/offad.jpg
title: Offensive Operations in Active Directory - Part 0x00
subtitle: Taming the three headed dog and making it our loyal companion
---
There is a [well known thought experiment](https://en.wikipedia.org/wiki/If_a_tree_falls_in_a_forest) that makes one wonder whether a tree falling in a forest, with no one around to hear the sound of it hitting the ground, actually makes a sound at all. Well, I don't know about you my friend, but I know nothing about trees falling and botany in general! What I do know however is the sound some people make (sysadmins, mostly) when they see a entire forest go down. Yep, I'm talking Active Directory forests. Trust me, it's traumatic.

Ok, now that I have overtaken blank page anxiety (bear with me okay?) we can start talking more seriously. Recently I was involved in a internal penetration test of a big organization which had networks spread across many European countries. It was a multi-step operation, with my work being the second step, after the initial compromise performed by other guys who landed a shell on the frontend through a web application. I was tasked with further developing the beachhead inside the target network and taking control of their multi-forest environment. 

I expected some sort of a challenge, but what I found instead was a complete mess (from the security point of view of at least). A mess so big that in less than twenty minutes I had full control over two of their three forests, with only the third one missing. It took me roughly a day to compromise the third forest, mainly because I was slowed down by trying to get my head around the amount of information I had at my disposal, as we had to compile a report at the end of the operation and make the C-level understand that a compromised Active Directory forest means the attacker has full access to everything the forest contains: backups, databases, applications' sources, the clients' financial information... Take note folks, inventorize everything you loot! With the last forest compromised I really had it all, including the servers' iLO interfaces (which can be used to obtain some pretty interesting kinetic effects as you can literally shut down the servers' cooling fans) and the Virtual Machine Manager (VMM) console, from which I could basically CTRL-A + DEL the entire infrastructure. All in all, ~~an amusing operation~~ something that will take months to secure properly.

| ![watchdogs screens]({{site.baseurl}}/img/screens.jpg) |
|:--:|
| *Yep, that's how it felt* |
