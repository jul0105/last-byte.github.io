---
layout: post
published: true
image: /img/offad.jpg
title: 'Offensive Operations in Active Directory #0'
subtitle: Taming Kerberos and making it our loyal companion
date: '2020-05-07'
---
_To all the evil men doing good things_  
_And to my friend [Vito](https://twitter.com/Trust_No_001)_  
_Who started me down the path_  
_Of AD black wizardry_

There is a [well known thought experiment](https://en.wikipedia.org/wiki/If_a_tree_falls_in_a_forest) that makes one wonder whether a tree falling in a forest, with no one around to hear the sound of it hitting the ground, actually makes a sound at all. Well, I don't know about you my friend, but I know nothing about trees falling and botany in general! What I do know however is the sound some people make (sysadmins, mostly) when they see a entire forest go down. Yep, I'm talking Active Directory forests. Trust me, it's traumatic.

Ok, now that I have overtaken blank page anxiety (bear with me okay?) we can start talking more seriously. Recently I was involved in a internal penetration test of a big organization which had networks spread across many European countries. It was a multi-step operation, with my work being the second step, after the initial compromise performed by other guys who landed a shell on the frontend through a web application. I was tasked with further developing the beachhead inside the target network and taking control of their multi-forest environment. 

I expected some sort of a challenge, but what I found instead was a complete mess (from the security point of view of at least). A mess so big that in less than twenty minutes I had full control over two of their three forests, with only the third one missing. It took me roughly a day to compromise the third forest, mainly because I was slowed down by trying to get my head around the amount of information I had at my disposal, as we had to compile a report at the end of the operation and make the C-level understand that a compromised Active Directory forest means the attacker has full access to everything the forest contains: backups, databases, applications' sources, the clients' financial information... Take note folks, inventorize everything you loot!

With the last forest compromised I really had it all, including the servers' iLO interfaces (which can be used to obtain some pretty interesting kinetic effects as you can literally shut down the servers' cooling fans) and the Virtual Machine Manager (VMM) console, from which I could basically CTRL-A + DEL the entire infrastructure. All in all, ~~an amusing operation~~ something that will take months to secure properly.

| ![watchdogs screens]({{site.baseurl}}/img/screens.jpg) |
|:--:|
| *Yep, that's how it felt!* |

And here we arrive at the reason for this (short?) blog post series. Despite what some good friends of mine say (gne, [@Th3Zer0](https://twitter.com/Th3Zer0) and [@Smaury](https://twitter.com/smaury92)?) Active Directory is really interesting as a target, as it's a complicated mess of technologies and practices which technicians get wrong a Shitton™ of times! What I want to cover in these ~~useless rants~~ posts is the workings of the components that make (and often break) Active Directory environments. In this part (which is the zeroth one) we will have a look at how the ~~in~~famous Microsoft's implementation of the Kerberos authentication mechanism work, step by step. The idea of the series is to analyze each step, understand the assumptions behind it and how to turn those assumptions against our target. But first, da fuq's Kerberos?

## High level overview and terminology

At its core, Kerberos is an authentication protocol, period. It was first devised by the MIT, then Microsoft decided to use it (after customizing it a bit) as the basis for authentication across Active Directory. 

| ![kerberos mechanism]({{site.baseurl}}/img/kerberos.png) |
|:-:|
| *I suck at Visio, don't hate me...* |

At first it can seem complicated, but it really isn't. Kerberos revolves around three main concepts:
- The Key Distribution Center (KDC)
- Tickets
- Shared secret

Let's briefly discuss them. The KDC is the server responsible for authenticating the clients. In Microsoft's implementation of Kerberos, the KDC and the Domain Controller (DC) are the same machine, and from now on we will refer to the KDC as simply the DC. In Kerberos, clients do not directly connect to the service server (the machine that has the resource they want to access), they first have to request a ticket from the KDC. 

So what's a ticket? Simply put, a ticket is a piece of information, structured in a particular way, the client holds in memory. It becomes an authentication token the client provides to the service server so that the server can verify whether the client can access the resource or not. But how does a client request a ticket? It makes a special request encrypted with a shared secret that only the client and the DC can know. 

The shared secret, in Microsoft's implementation of Kerberos, is the NT hash of the user's password. For those of you wondering what a NT hash is: it's the official name of what's misleadingly known as NTLM hash. We will use the name "NTLM hash" from now on as its usage is widespread, but check [this post](https://medium.com/@petergombos/lm-ntlm-net-ntlmv2-oh-my-a9b235c58ed4) for a more complete overview of the different hashes algorithms Windows implements. How does the client and the DC know the shared secret without exchanging it before? Well, the client knows it as it is the NTLM hash of the user's password, while the DC knows it because it stores the passwords' hashes of all the users of the domain (duh?). As a reminder, the NTLM hash of a string is calculated using the following formula:
```
MD4(UTF-16-LE(string))
```
Which stands for the MD4 digest of the string encoded in the UTF-16 little endian format.

## Kerberos authentication step by step

Ok, now that terminology is out of the way, let's get to the authentication mechanism. I suggest you follow this while keeping along a tab with the [RFC 1510](https://tools.ietf.org/html/rfc1510), which is Kerberos' RFC, open. As we already said, before accessing a resource, a client needs to interact with the DC to get the information he needs in order to show the service server who he is (or, more precisely, claims to be). As you saw in the previous image, the Kerberos authentication mechanism is comprised of six mandatory step and two optional steps (I didn't draw the optional ones, as they are out of the scope of this series). The steps are numbered from 1 to 6:
1. Authentication Service - Request (AS-REQ)
2. Authentication Service - Response (AS-REP)
3. Ticket Granting Service - Request (TGS-REQ)
4. Ticket Granting Service - Response (TGS-REP)
5. Application Server - Request (AP-REQ)
6. Application Server - Response (AP-REP)

The odd numbered steps are initiated by the client, while the even ones by the DC. The two optional steps involve the service server verifying certain information provided by the client but this check is rarely enabled as it adds a ton of overhead to the overall authentication mechanism, potentially slowing down domain operations.

Now let's check what every single step does and how it appears from a network perspective with the help of our good friend Wireshark. You can find the PCAP file I'm using as example [right here](https://wiki.wireshark.org/SampleCaptures) in the Wireshark samples page. I'm using the [krb-816](https://wiki.wireshark.org/SampleCaptures?action=AttachFile&do=get&target=krb-816.zip) sample.

### Authentication Service - Request (AS-REQ)

The Authentication Service - Request (AS-REQ) is the first step. You can see it by opening packet number 3 of the sample we are analyzing. Here we have a packet which holds two pieces of information. The first piece can be found inside the "padata" header and contains a timestamp encrypted with the NTLM hash of the user's password. The second piece is inside the "req-body" field and contains cleartext information regarding the username, the domain, the client hostname and so on. Let's take a deeper look.

```
Kerberos
    as-req
        pvno: 5
        msg-type: krb-as-req (10)
        padata: 2 items
            PA-DATA PA-ENC-TIMESTAMP
                padata-type: kRB5-PADATA-ENC-TIMESTAMP (2)
                    padata-value: 3049a003020103a106020400a2f790a23a0438233b4272aa…
                        etype: eTYPE-DES-CBC-MD5 (3)
                        kvno: 10680208
                        cipher: 233b4272aa93727221facfdbdcc9d1d9a0c43a2798c81060…
            PA-DATA PA-PAC-REQUEST
                padata-type: kRB5-PADATA-PA-PAC-REQUEST (128)
                    padata-value: 3005a0030101ff
                        include-pac: True
        req-body
            Padding: 0
            kdc-options: 40810010
            cname
                name-type: kRB5-NT-PRINCIPAL (1)
                cname-string: 1 item
                    CNameString: des
            realm: DENYDC
            sname
                name-type: kRB5-NT-SRV-INST (2)
                sname-string: 2 items
                    SNameString: krbtgt
                    SNameString: DENYDC
            till: 2037-09-13 02:48:05 (UTC)
            rtime: 2037-09-13 02:48:05 (UTC)
            nonce: 197451134
            etype: 2 items
                ENCTYPE: eTYPE-DES-CBC-MD5 (3)
                ENCTYPE: eTYPE-DES-CBC-CRC (1)
            addresses: 1 item XP1<20>
                HostAddress XP1<20>
                    addr-type: nETBIOS (20)
                    NetBIOS Name: XP1<20> (Server service)
```

Don't worry, we are not going to focus on every single byte of the packet, but there are a few fields you have to understand:

- `as-req`: this line tells us this is a AS-REQ Kerberos packet
- `pvno`: stands for Protocol Version Number, which is version 5 (the recurring KRB5)
- `padata`: holds the Pre-Authentication data. Here we have the `PA-DATA PA-ENC-TIMESTAMP` section. Which type of data this section holds is explained by the `padata-type` field, that tells us it's a "kRB5-PADATA-ENC-TIMESTAMP", our encrypted timestamp. The encrypted value is held by the `padata-value` field of this section
- `req body`: this is where the cleartext part of the request is kept
- `kdc-options`: this is a collection of flags used to enable certain features for the ticket which will be returned by the KDC (spoilers)
- `cname`: this section holds the username the client is trying to authenticate. To be more specific, the exact username in this case is "des" and the data is held in the `CNameString` field
- `realm`: this is the domain name in the netbios format. Its value is "DENYDC"
- `sname`: this section holds the service the client is targeting. Since this is an AS-REQ packet, the service will be the krbtgt (which is the domain user who manages most of the Kerberos operations, we'll get to him later) of the domain (DENYDC)
- `till`: (valid unTILL) this is the expiration date of the ticket which will be issued by the DC (spoilers)
- `rtime`: this is the absolute expiration time of the ticket which will be issued if the renewable flag was set (other spoilers)
- `addresses`: this section contains the host address. In this case the address is a NETBIOS type address, as specified by the `addr-type` field, and its value is "XP1", which can be read in the `NetBIOS Name` field


