---
layout: post
published: true
image: /img/IMG_6264.jpg
date: '2019-01-23'
title: Securing Your Macbook Part 2
subtitle: 'Separating Privileges (2): different accounts for different privilege levels'
---
# Introduction
Quick recap of what we saw in the [last post](https://blog.notso.pro/2019-01-21-securing-your-macbook/). In the first part of this serie we saw how to create a new user and allow only him to unlock FV2. This effectively allows having different passwords for FV2 decryption and user authentication.
  
In this short post we will see how to segregate privileges and have an account ONLY for administrative purposes and one for everyday tasks. The reason behind this is that if your everyday account gets compromised for whatever reason (browser 0day? Wrong email attachment? TotallyNotMalware.dmg?) it won't have access to superuser capabilities and/or `sudo`.

These are the actions we will take:
1. Add a new account with administrative privileges
2. Demote our everyday account to standard privileges
3. Cast some spells using the terminal to clean everything up

<p class="alert alert-warning">
    <span class="label label-warning">CAUTION:</span> if not done right this procedure can lead you to lose administrative privileges of your Macbook and it will be a royal pain in the butt to gain them back, so follow carefully. As always, what you do with your machine is all under your responsibility, don't blame me if your Macbook freezes, catches fire, becomes a Decepticon and starts attacking you with lasers for seemingly no reason.
</p>
<br>
### 1. Add a new account with administrative privileges
This is pretty straightforward: open up <mark>System Preferences</mark>, then go to <mark>Users & Groups</mark>. Then click on the <mark>little plus sign</mark> on the left. From the drop down menu near "New Account" select <mark>"Administrator"</mark>. Go ahead and fill up the other fields.
<p class="alert alert-warning">
    <span class="label label-warning">CAUTION:</span> remember the password of this account and make sure you don't lose it. I know it should be obvious but you never know.
</p>
<br>
### 2. Demote our everyday account to standard privileges
Now it's time to say goodbye to your powers. But first, you have to log off your soon-to-be standard account and log into your newly created admin account. This serves two purposes: first, to make sure you didn't mistype the password at user creation; second, because macOS doesn't allow user privilege demoting while the user is logged on. Once your user environment is ready, go back to <mark>System Preferences</mark> and then to <mark>Users & Groups</mark>. From there <mark>left click on your everyday account and uncheck "Allow user to administer this computer"</mark> at the bottom. Now log off and log in your standard account.

Notice that now, if you open up the terminal and try running `sudo su`, after entering the password, the terminal will get mad at you, insult you and tell you you aren't worthy of possessing the power of ~~Thor~~ root.
<br>
### 3. Cast some spells using the terminal to clean everything up
Nice and easy until now right? And it will stay that way, only that now it's time to fire up the terminal to clean one or two things. Assuming your administrator account is named `antani`, run the following command to make sure `/etc/sudoers` file is alright:

```
$ su antani
$ sudo cat /etc/sudoers
```

The part under `# User specification` should look like the following:

```
##
# User specification
##

# root and users in group wheel can run anything on any machine as any user
root		ALL = (ALL) ALL
%admin		ALL = (ALL) ALL
```

where the line `root		ALL = (ALL) ALL` means that root can do everything (well, you know... it's root) and the line `%admin		ALL = (ALL) ALL` means that all the accounts beloging to the `admin` group (and that means `antani` too) can use sudo to run anything. Just make sure that <mark>no other account except for root and the admin group shows up in the sudoers file unless you specifically intended so</mark>.
<p class="alert alert-info">
    <span class="label label-info">NOTE:</span> the following part is for those who went through the first part of this serie as your new account can now decrypt FV2.
</p>

In case you don't want your newly created admin account to be able to decrypt FV2 run the following command (again, I'm assuming your newly created account's username is `antani`):

```
$ su antani
$ sudo fdesetup remove -user antani
```
<p class="alert alert-warning">
    <span class="label label-warning">CAUTION:</span> the whole point of this part was to make sure the admin account is used strictly for administrative purposes and NOTHING else. That means not even decrypting FV2. This is to avoid that an attacker that may have seen you while decrypting FV2 using your admin account can use that information to later escalate privileges on your machine.
</p>
<p class="alert alert-success">
    <span class="label label-success">SUCCESS:</span> now you have different accounts with different privileges. It's less likely that an attacker compromising your everyday account can escalate privileges by just running <code>sudo su</code>. 
</p>

In the following posts we will see how to add a sort of two factor authentication to user login using a Yubikey.
