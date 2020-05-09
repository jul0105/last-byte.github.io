---
layout: post
published: false
image: /img/offad.jpg
title: 'Offensive Operations in Active Directory #1'
subtitle: Scatter the (h)ashes...
date: '2020-05-09'
---
Greetings fellow hackers! Last here, today we will take a look at a well known technique used by attackers in AD environments, the infamous *overpass-the-hash*.

"BuT lAsT, pAsS tHe HaSh iS sO 1997!11!1!!" you could say. And you would be right, partly. Time for an anecdote! It was the beginning of 2018 and I was attending a conference with some teammates. A guy was giving a talk about attacking Active Directory and at some point he talked about the _pass-the-hash_ attack. One of my mates (who definitely was not [G](https://twitter.com/0x1911), I swear!) said "Come on, 2018 and people are still talking about passing the hash?". 

Well G, here I am, Anno Domini 2020 and still talking about (over)passing the hash!

| ![anatomy]({{site.baseurl}}/img/anatomylesson.jpg) |
|:--:|
| *I was hoping for another kind of "internals"* |

Jokes aside, _pass-the-hash_ (PtH) and _overpass-the-hash_ (OPtH) are actually two different attack techniques: the old PtH involved directly authenticating to a host by literally sending the password's hash to the host during the authentication process, while OPtH is way more subtle as it abuses Kerberos authentication. 

## The shared secret problem

Quick recap: [as we discussed in the last post](https://blog.notso.pro/2020-05-07-offops-in-ad-0/), Kerberos is built upon shared secrets. When implementing Kerberos in Active Directory, Microsoft decided the shared secret would be the NTLM hash of the user trying to authenticate. So when a user wants to authenticate, the client machine takes the timestamp, encrypts it using the user's NTLM hash and sends it to the DC, alongside the unencrypted username and domain. Upon receiving the packet, the DC reads the username, fetches his password's NTLM hash from its local database and uses it to decrypt the timestamp. If it's valid, the DC generates a TGT for that user, encrypts it with krbtgt's password's NTLM hash and sends it back to the client, who can use that TGT to request TGSs on behalf of the user and authenticate to services.

![AS-REQ&REP]({{site.baseurl}}/img/asreqrep.png)

As you may have realized by now, the entire security of this step relies on the secrecy of the NTLM hash of the user's password. I will repeat it, here security relies on the secrecy of the hash, not of the password. But hashes are secure right? They are only stored on the DC right? And on clients they are not stored but calculated on the fly when the user inputs his password, right? Wrong.

## Fantastic ~~beasts~~ hashes and where to find them

In the Marvelous Cybersecurity Universe (not to be confused with the other and more famous MCU) hashes can be collected pretty much anywhere: data leaks, breaches, etc. However, the type of hash we are concerned with can actually be found inside domain-joined compromised machines on which we have administrative privileges. I'll skip the privilege escalation process, as it's out of scope for this post and as there are tons of ways to end up SYSTEM on a machine. For now, let's limit ourselves to think we have compromised a client inside our target network. Where are them hashes, yo? A very special process called Local Security Authority Subsystem Service (LSASS) can help us.

To quote the [official and omniscient Microsoft documentation](https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-r2-and-2012/hh994565(v=ws.11)):
> The Local Security Authority Subsystem Service (LSASS) stores credentials in memory on behalf of users with active Windows sessions. This allows users to seamlessly access network resources, such as file shares, Exchange Server mailboxes, and SharePoint sites, without re-entering their credentials for each remote service.
> LSASS can store credentials in multiple forms, including:
> - Reversibly encrypted plaintext
> - Kerberos tickets (TGTs, service tickets)
> - NT hash
> - LM hash

If that's not the definition of "goldmine", I don't know what is! ¯ \\\_(ツ)_/¯

The LSASS process can be spotted using Task Manager (or Process Explorer) if you head to the "Details" tab.

| ![lsass]({{site.baseurl}}/img/lsass.PNG) |
|:--:|
| *Kids, I'm a trained professional and this is a virtualized lab environment. Never ever log in as your Domain's Administrator.* |

One way to obtain the credentials stored in memory would be to dump the entire machine's memory, but that would be noisy and would generate a big DMP file. The cleaner way is to just target the LSASS process and selectively dump it. Still noisy and sketchy, but still way less than `cat /dev/motherfuckingeverything > memory.txt`. 

As you can see, LSASS runs under the SYSTEM privilege context, so to dump its address space we need administrative privileges (life sucks, I know). One way it can be achieved is through Task Manager itself, by right clicking on lsass.exe and selecting "Create dump file". In this way we don't need to upload any suspicious executable on the target machine, as we can then download the DMP file and extract the credentials offline. This can be achieved through the Volatility Framework, Mimikatz or your own custom tools. Let's see an example: I dumped the credentials on my lab machine using Task Manager and exported the resulting lsass.DMP file on Windows VM on which I have Mimikatz. 

