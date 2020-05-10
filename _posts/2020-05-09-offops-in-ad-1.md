---
layout: post
published: true
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

So basically, Windows' Local Security Authority (LSA) uses the LSASS process' address space to store the credentials of logged in users. That allows users with sufficiently high privileges to dump the address space of LSASS and extract the credentials of all the users who logged on the machine since the last restart. If that's not the definition of "goldmine", I don't know what is! ¯ \\\_(ツ)_/¯

The LSASS process can be spotted using Task Manager (or Process Explorer) if you head to the "Details" tab.

| ![lsass]({{site.baseurl}}/img/lsass.PNG) |
|:--:|
| *Kids, I'm a trained professional and this is a virtualized lab environment. Never ever log in as your Domain's Administrator.* |

One way to obtain the credentials stored in memory would be to dump the entire machine's memory, but that would be noisy and would generate a big DMP file. The cleaner way is to just target the LSASS process and selectively dump it. Still noisy and sketchy, but still way less than `cat /dev/motherfuckingeverything > memory.txt`. 

As we said before, to dump LSASS address space we need administrative privileges (life sucks, I know). One way it can be achieved is through Task Manager itself, by right clicking on `lsass.exe` and selecting "Create dump file". In this way we don't need to upload any suspicious executable on the target machine, as we can then download the DMP file and extract the credentials offline. This can be achieved through the [Volatility Framework](https://github.com/volatilityfoundation/volatility), [Mimikatz](https://github.com/gentilkiwi/mimikatz) or your own custom tools. 

Let's see an example: I dumped the credentials on my lab machine using Task Manager and exported the resulting lsass.DMP file on a Windows VM on which I have Mimikatz.

To extract credentials from the dump file we first have to tell Mimikatz to switch its context and target the dump. After that, we run the usual logon passwords dumping command. Here are the commands to execute:

```
mimikatz # sekurlsa::minidump <path_to_file>
mimikatz # sekurlsa::logonpasswords
```

In my case the path to file was `C:\Users\last\Desktop\lsass.DMP`. That's the end result:

![minidump1]({{site.baseurl}}/img/minidump1.PNG)

On a normal domain-joined machine, Mimikatz's `sekurlsa::logonpassword` often returns a lot of output, so you need to sort through it to find what you are really looking for:

![minidump2]({{site.baseurl}}/img/minidump2.PNG)

Now that's the kind of stuff you, as an attacker, want to see. Let's dissect this output and see what we have here:

```
Authentication Id : 0 ; 301367 (00000000:00049937)
Session           : Interactive from 1
User Name         : Administrator
Domain            : TARGETNET
Logon Server      : DC1
Logon Time        : 5/9/2020 4:35:15 AM
SID               : S-1-5-21-2283460142-4117294090-2784357223-500
        msv :
         [00000003] Primary
         * Username : Administrator
         * Domain   : TARGETNET
         * NTLM     : 007461b27da66eded419e8db22307c4f
         * SHA1     : 5cf7a0c33b82ffe9f95ff8ed364b665aa2d1df93
         * DPAPI    : 6b52635072d946e875936739e00bf004
        tspkg :
        wdigest :
         * Username : Administrator
         * Domain   : TARGETNET
         * Password : (null)
        kerberos :
         * Username : Administrator
         * Domain   : TARGETNET.NOTSO.PRO
         * Password : (null)
        ssp :
        credman :
```
So here, what we really need to focus is:
- Session: "Interactive" means this the user is physically logged on the machine. If you saw "RemoteInteractive" for example it could mean someone might have logged in using RDP
- User Name: this is the UI rendered username, which can be different from the effective username used to login
- Domain: this is the Kerberos realm we talked about in [the last post](https://blog.notso.pro/2020-05-07-offops-in-ad-0/).
- Logon Server: this tells us the netbios name of the Domain Controller to which the user authenticated
- Logon Time: this is the time at which the user authenticated
- SID: this is the user Security Identifier of the account. You can read more about SIDs on the [official documentation](https://docs.microsoft.com/it-it/windows/security/identity-protection/access-control/security-identifiers). We will talk about them more in depth in later posts, for now you just need to know it's a unique ID assigned to each object and used by Windows to manage security stuff
- Username: this is the string used as username
- NTLM: this is the NTLM hash of the password, the data we were looking for :D 

By the way, check out [Mimikatz's wiki](https://github.com/gentilkiwi/mimikatz/wiki) as it's full of really useful information :)

## Piecing it all together

Let's recap what we needed to authenticate as a user:
- [x] Username
- [x] Domain name
- [x] Timestamp
- [x] NTLM hash

There are many ways to spawn a process as a new user, the quickiest and most common is to use Mimikatz once again. Here's the syntax:

```
mimikatz # sekurlsa::pth /user:<username> /domain:<domain> /ntlm:<hash> /run:<executable>

EXAMPLE:
mimikatz # sekurlsa::pth /user:Administrator /domain:targetnet.notso.pro /ntlm:007461b27da66eded419e8db22307c4f /run:powershell.exe
```

The `pth` command of Mimikatz's `sekurlsa` module is the one responsible for executing _overpass-the-hash_ attacks. How does it do it? To quote [Mimikatz's wiki](https://github.com/gentilkiwi/mimikatz/wiki/module-~-sekurlsa):

> Mimikatz can perform the well-known operation 'Pass-The-Hash' to run a process under another credentials with NTLM hash of the user's password, instead of its real password.
> For this, it starts a process with a fake identity, then replaces fake information (NTLM hash of the fake password) with real information (NTLM hash of the real password).

So basically it injects the identity we provide inside a freshly spawned process. Here is how it happens: first we open an administrative level powershell (or cmd, it's the same) and execute Mimikatz. Once inside it, we execute the command listed above:

![mimikatz1]({{site.baseurl}}/img/mimikatz1.PNG)

Mimikatz ran just fine and presented us with some information about the newly spawned process:
- user: the username of the user owning the new process
- domain: the domain of the user owning the new process
- program: the executable that has been ran
- impers.: this field tells us we didn't specify the `/impersonate` option, which doesn't spawn a new process, but directly injects the process running Mimikatz (the first powershell)
- NTLM: the NTLM hash of the user owning the new process
- PID: the Process Identifier of the new process
- TID: the Thread Identifier of the main thread of the new process

After the command ran a new powershell session opened. 

![mimikatz2]({{site.baseurl}}/img/mimikatz2.PNG)

As you can see, the PID of the new powershell process (contained within the `$PID` environment variable) is the same as the one specified by the previous screenshot. 

You may have noticed the output of the `whoami` command running locally is different from the output of the `whoami` command ran through `Invoke-Command` on `dc1.targetnet.notso.pro` (the DC). That's because local `whoami` returns information on the user currently logged on, which is `targetnet\last`, while the remote one runs in the context of the user authenticated through Kerberos on the DC, which is `targetnet\administrator`. When at the beginning of my journey I remember I ran Mimikatz a thousand times, only to get angry and immediately close the new process as `whoami` returned the wrong user, because I did not know the difference and what was happening behind the scenes. To quote [LiveOverflow](https://www.youtube.com/channel/UClcE-kVhqyiHCcjYwcpfj9w):

![skiddie](https://liveoverflow.com/content/images/2019/05/The_Origin_of_Script_Kiddie_Hacker_Etymology.gif)

As you also may have seen I ran the `klist` command, which lists imported Kerberos tickets. The first and the second are TGTs (don't ask me why I have two, I'll ping a friend of mine who surely knows it), while the third one is a TGS. 


| ![tgs]({{site.baseurl}}/img/klist.png) |
|:--:|
| *The TGS issued to run PS Remoting commands* |

Let's break them down:
- Client: the user who requested the ticket. We can see it's `Administrator @ TARGETNET.NOTSO.PRO`, the Domain's Administrator account
- Server: in the first and the second it's `krbtgt/TARGETNET.NOTSO.PRO @ TARGETNET.NOTSO.PRO` which is the krbtgt's service, the one responsible for Kerberos authentication and TGT issuing. In the third ticket it's `HTTP/dc1.targetnet.notso.pro @ TARGETNET.NOTSO.PRO`, meaning it's a TGS for the HTTP service of the DC. This has been issued because we ran `Invoke-Command`, which is a Powershell Remoting command, and PS Remoting uses a HTTP as protocol for trasmission of commands and output. Sometimes you may also see a TGS for the HOST service, always because of PS Remoting
- Start Time: the time from which the ticket will become valid
- End Time: the time on which the ticket will expire unless renewed
- Renew Time: the time on which renewed tickets will finally expire
- Kdc Called: the Key Distribution Center (aka the Domain Controller) which issued the ticket

## Conclusion

Ok, I think it's enough as explaination for this attack. Attacks like this are "easy" because great professionals (like [Gentilkiwi](https://twitter.com/gentilkiwi)) go to great lengths to allow us to employ to wield tools like this and perform security assessments. As you may have seen there is always more than meets the eye and I'm convinced that knowing the basics behind attacks as "simple" as this one will always make us better professionals. And it also allows us to replicate the attack by writing our own custom ~~and undetectable~~ tools :)

See you soon,
last, out.



