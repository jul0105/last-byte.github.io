---
layout: post
published: false
image: /img/offad.jpg
title: 'Offensive Operations in Active Directory #1'
subtitle: Scatter the (h)ashes...
date: '2020-05-09'
---
Greetings fellow hackers! Last here, today we will take a look at a well known technique used by attackers in AD environments, the infamous *overpass-the-hash*.

"bUt lAsT, pAsS tHe HaSh iS sO 1997!11!1!!" you could say. And you would be right, partly. Time for an anecdote! It was the beginning of 2018 and I was attending a conference with some teammates. A guy was giving a talk about attacking Active Directory and at some point he talked about the _pass-the-hash_ attack. One of my mates (who definitely was not [G](https://twitter.com/0x1911), I swear!) said "Come on, 2018 and people are still talking about passing the hash?". 

Well G, here I am, Anno Domini 2020 and still talking about (over)passing the hash!

| ![anatomy]({{site.baseurl}}/img/anatomylesson.jpg) |
|:--:|
| *I was hoping for another kind of "internals"* |

Jokes aside, _pass-the-hash_ (PtH) and _overpass-the-hash_ (OPtH) are actually two different attack techniques: the old PtH involved directly authenticating to a host by literally sending the password hash to the host during the authentication process, while OPtH is way more subtle as it abuses the first step of Kerberos authentication. 

## The shared secret problem

Quick recap: [as we discussed in the last post](https://blog.notso.pro/2020-05-07-offops-in-ad-0/), Kerberos is built upon shared secrets. When implementing Kerberos in Active Directory, Microsoft decided the shared secret would be the NTLM hash of the user trying to authenticate. So when a user wants to authenticate, the client machine takes the timestamp, encrypts it using the user's NTLM hash and sends it to the DC, alongside the unencrypted username and domain. Upon receiving the packet, the DC reads the username, fetches his password's NTLM hash from its local database and uses it to decrypt the timestamp. If it's valid, the DC generates a TGT for that user, encrypts it with krbtgt's password's NTLM hash and sends it back to the client, who can use that TGT to request TGSs on behalf of the user and authenticate to services.

![AS-REQ&REP]({{site.baseurl}}/img/asreqrep.png)

As you may have realized by now, the entire security of this step relies on the secrecy of the NTLM hash of the user's password. I will repeat it, here security relies on the secrecy of the hash, not of the password. But hashes are secure right? They are only stored on the DC right? And on clients they are not stored but calculated on the fly when the user inputs his password, right? Wrong.

## Fantastic ~~beasts~~ hashes and where to find them






