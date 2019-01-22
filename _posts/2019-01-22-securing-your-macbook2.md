---
layout: post
published: true
image: /img/IMG_6264.jpg
date: '2019-01-21'
title: Securing Your Macbook Part 2
subtitle: 'Separating Privileges (2): different accounts for different privilege levels'
---
# Introduction
Quick recap of what we saw in the [last post](https://blog.notso.pro/2019-01-21-securing-your-macbook/). In the first part of this serie we saw how to create a new user and allow only him to unlock FV2. This effectively allows having two different passwords for FV2 decryption and user authentication.
  
In this short post we will see how to segregate privileges and have an account ONLY for administrative purposes and one for everyday tasks. The reason behind this is that if you everyday account gets compromised for whatever reason (browser 0day? Wrong email attachment? TotallyNotMalware.dmg?) it won't have access to superuser capabilities and/or `sudo`.

These are the actions we will take:
1. Add a new account with administrative privileges
2. Demote our everyday account to standard privileges
3. Cast some spells using the terminal to clean everything up

<p class="alert alert-warning">
    <span class="label label-warning">CAUTION:</span> if not done right this procedure can lead you to losing administrative privileges of your Macbook and it will be a royal pain in the butt to gain them back so follow carefully. As always, what you do with your machine is all under your responsibility, don't blame me if your Macbook freezes, catches fire, becomes a Decepticon and starts attacking you with lasers for seemingly no reason.
</p>
<br>
### 1. Add a new account with administrative privileges
This is pretty straightforward: open up <mark>System Preferences</mark>, then go to <mark>Users & Groups</mark>. Then click on the <mark>little plus sign</mark> on the left. From the drop down menu near "New Account" select <mark>"Administrator"</mark>. Go ahead and fill up the other fields.
<p class="alert alert-warning">
    <span class="label label-warning">CAUTION:</span> remember the password of this account and make sure you don't lose it. I know it should be obvious but you never know.
</p>
<br>
### 2. Demote our everyday account to standard privileges
Now it's time to say goodbye to your powers. But first, you have to log off your soon-to-be standard account and log into your newly created admin account. This serves two purposes: first, to make sure you didn't mistype the password at user creation; second, because macOS doesn't allow user privilege demoting while the user is logged on. Once your user is setup go back to <mark>System Preferences</mark> and then to <mark>Users & Groups</mark>. From there <mark>left click on your everyday account and uncheck "Allow user to administer this computer"</mark> at the bottom.






