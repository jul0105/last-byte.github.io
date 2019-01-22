---
layout: post
published: true
title: 'Securing Your Macbook Part 1: Separating Privileges'
---
# Introduction
This is a blogpost serie on how I keep my Macbook ~~in~~secure. These posts take a lot from the following resources so kudos to them first:

- [macOS Security and Privacy Guide ](https://github.com/drduh/macOS-Security-and-Privacy-Guide)
- [Configuring macOS Sierra to authenticate with YubiKey 4](https://medium.com/@ellenbeldner/configuring-macos-sierra-to-authenticate-with-yubikey-4-876a8ab81e07)

The idea behind this is to make it ~~impossible~~ very difficult for an attacker to take control of your device even with physical access. Impossible is nothing, and that's even more true in the security industry. 

<p class="alert alert-warning">
    <span class="label label-warning">CAUTION:</span> always expect a skilled and resourceful attacker to be able to fully compromise your device with physical access, it's just a matter of time.
</p>

That does not mean you have to make it easier for him to compromise you: the more time you buy, the less likely the information he will retrieve will be of any use.

In this first part we are going to take a look at privilege separation in macOS (I will be using macOS 10.14 Mojave but the same principles theoretically apply for the other versions). The idea is to have separate accounts for separate "privilege levels" and by that I mean having AT LEAST two accounts and AT BEST three accounts: one for administrative purposes which can use `sudo`, one for everyday tasks and one capable of decrypting FileVault2 (you do encrypt your laptop, right?).


<p class="alert alert-warning">
    <span class="label label-warning">CAUTION:</span> be very careful, especially in the part where we will be giving FV2 decryption capabilities to just one account. If you manage to lose the decryption password or something bad happens you better have backups. In case you didn't figure it out by yourself, I take no responsibility if you f**k up your machine :)
</p>

<br><br>
### Different passwords for FV2 decryption and user authentication
<p class="alert alert-info">
    <span class="label label-info">NOTE:</span> I'm assuming you have already enabled FileVault2 (FV2 from here on) encryption on your device. If it's not your case, google how to enable it NOW.
</p>

This is technically the easiest section so we will start with it. These are the steps we will follow in order to achieve our goal: having different passwords for FV2 decryption and user authentication.


1. Creating a new user
2. Disabling FV2 autologin feature
3. Disabling FV2 decryption capabilities for standard users

<br><br>
#### Creating a new user
In order to create a new user you should go into the <mark>System Preferences</mark>, then <mark>Users & Groups</mark> and click on the <mark>little plus sign</mark> on the left.

<p class="alert alert-info">
    <span class="label label-info">NOTE:</span> remember the "Account Name" you are setting, we will need it later. For this guide we will use "DecryptFV" as Account Name, remember in macOS usernames are case sensitive. In "Full Name" you can write whatever you want, it will be the name displayed when you decrypt FV2. Set it to something like "Decrypt FileVault".
</p>
<p class="alert alert-warning">
    <span class="label label-warning">CAUTION:</span> be sure to remember the password you are setting for this account as it will be the password you will use to decrypt FV2.
</p>

After creating the new user, click on the <mark>Login Options</mark> and uncheck <mark>Show fast user switching menu as... </mark>.  
  
Once you have created the account fire up the terminal and write the following commands (remember to change the name of the account if you did not use "DecryptFV" like me):  
  
`sudo dscl . create /Users/DecryptFV IsHidden 1`  
<br>
`sudo defaults write /Library/Preferences/com.apple.loginwindow SHOWOTHERUSERS_MANAGED -bool NO`  

In this way we have made the new user hidden so that it's not visible at login and we have also hidden the "Other Users" button which would have shown up because of the presence of hidden users.

<br><br>
#### Disabling FV2 autologin
Out of the box macOS does not allow different accounts for FV2 decryption and user login. However this feature can be enabled by running the following command:  
  
`sudo defaults write /Library/Preferences/com.apple.loginwindow DisableFDEAutoLogin -bool YES`  
  
  
Now, before we disable the other users, reboot your machine and make sure you can decrypt FV2 and login with the new account.

<br><br>
#### Disabling FV2 decryption capabilities for standard users
Ok, now it's time to allow only the new user to decrypt FV2, to do it run the following command for every user except for the one we just created:  
  
`sudo fdesetup remove -user <insert here the username>`  

<p class="alert alert-info">
    <span class="label label-info">NOTE:</span> Be sure to remove the <> brackets from the command.
</p>




