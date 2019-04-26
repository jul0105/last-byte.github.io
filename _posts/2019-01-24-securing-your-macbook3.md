---
layout: post
published: true
image: /img/IMG_6264.jpg
date: '2019-01-24'
title: Securing Your Macbook Part 3
subtitle: '2FA at login: using Yubikeys as a second authentication layer'
---
# Introduction
Quick recap of what we saw in the [first](https://blog.notso.pro/2019-01-21-securing-your-macbook/) and [second](https://blog.notso.pro/2019-01-23-securing-your-macbook2/) parts of this series. We started out by seeing how to setup your Macbook so that only one account is allowed to decrypt FileVault2, effectively creating two different passwords for mass storage decryption and user login authentication. After that we saw how to further compartmentalize by creating an account with administrative privileges, used only for administrative tasks like installing new software, adding new accounts or changing system preferences, and demoting our own user to standard account in order to make it harder for an attacker that has compromised it to escalate privileges and gain full control of the device.

In this part of the series we will see how to use a [Yubikey](https://www.yubico.com/) to obtain a form of [two factor authentication (2FA)](https://en.wikipedia.org/wiki/Multi-factor_authentication) at user login. The end result will be that to access your account you will have to provide your password and have the Yubikey inserted in your laptop. This measure can be also applied to secure the use of the command `sudo`.

<p class="alert alert-warning">
    <span class="label label-warning">CAUTION:</span> make sure you repeat this procedure twice with two different Yubikeys, you don't want to lose the only one you have and get locked out of your own machine.
</p>
<p class="alert alert-info">
    <span class="label label-info">NOTE:</span> it's possible to use the Yubikey as a PIV-compatible smart card with a pin for user login instead of the password. While some people and organizations use it that way I don't think it's really a good idea as the pin is at best a 8-character-long number, I think it's better to use a strong password and the Yubikey as a physical token.
</p>

These are the steps we will follow in order to achive our goal:
1. Configure the Yubikey second slot to provide a challenge-response authentication mechanism
2. Setup the challenge-response for every account
3. Modify PAM configuration files to require the Yubikey.

<br>
### 1. Configure the Yubikey second slot to provide a challenge-response authentication mechanism
<p class="alert alert-info">
    <span class="label label-info">NOTE:</span> if you went through the second part of this series you shouldn't be able to run <code>sudo</code> directly from the terminal. That means that everytime you will read a command prepended by <code>sudo</code> you will need to run <code>su admin_accout</code> in order to then run the command with <code>sudo</code>
</p>
First things first, we need the right software. We will install the [Yubikey Manager](https://www.yubico.com/products/services-software/download/yubikey-manager/) tool by Yubico and the Yubikey module for Pluggable Authentication Modules (PAM). The first can be downloaded by the link provided above and installed through the GUI while the second requires the installation through [MacPorts](https://www.macports.org/).
<p class="alert alert-info">
    <span class="label label-info">NOTE:</span> if you haven't installed MacPorts yet go to the link and install it. I've had a bad experience on Mojave using brew to install the yubico-pam module so I suggest you use MacPorts.
</p>
To install the module needed to interface the Yubikey with PAM we will run the following command:
```
sudo port install yubico-pam
```
We have got all the software we need, now we will proceed to setup the Yubikey. It can be done via the CLI but I think using Yubikey Manager is a bit more intuitive.

Insert the Yubikey in your Macbook, then open up Yubikey Manager. Click on <mark>Applications</mark> and select <mark>OTP</mark>. Where it says <mark>Long Touch (Slot 2)</mark> click <mark>Configure</mark>. Select <mark>Challenge-response</mark> and click <mark>Next</mark>. Now click <mark>Generate</mark> in order to generate a new secret that will be stored on your Yubikey. Optionally you can select <mark>Require touch</mark> if you want your Yubikey to be triggered and answer the challenge only if you touch the button on it.

<br>
### 2. Setup the challenge-response for every account
Now it's time to setup the challenge-response mechanism for every user. Remove and insert again your Yubikey, then fire up the terminal and write the following command:
```
$ ykpamcfg -2 
```
<p class="alert alert-info">
    <span class="label label-info">NOTE:</span> there's a good chance the command will fail with the following error if you have demoted your user to standard account:
	<br><br>
  	<code>
		last@lastBook: ~ $ ykpamcfg -2
	</code>
  	<br>
  	<code>
      	USB error: kIOReturnSuccess
	</code>
	<br><br>
	If that's the case run the following commands:
	<br><br>
	<code>
		$ cd
	</code>
  	<br>
    <code>
  		$ mkdir -m0700 .yubico
	</code>	
  	<br>
    <code>
  		$ cd .yubico
	</code>
  	<br>
  	<code>
      	$ sudo ykpamcfg -2
	</code>
  	<br>
  	<code>
      	$ cp /var/root/.yubico/challenge-* ./
	</code>
  	<br>
  	<code>
      $ sudo chown $(pwd | cut -d/ -f 3) ./challenge-*
	</code>
	<br><br>
	These commands basically <code>cd</code> in your home directory, create the <code>.yubico</code> directory where the files for your challenge-response will be stored, <code>cd</code> inside the directory, create the challenge-response files with <code>sudo ykpamcfg -2</code>, move them from where they are first created to the users's <code>.yubico</code> directory and change the owner of the files from root to the user that owns the directory.
</p>

Alright, now you have the challenge files in the `.yubico` directory inside your home directory. Repeat the procedure for every account in your laptop (this <mark>INCLUDES</mark> the administrative account and the decryption account). Once you have done that it's time to move to the third step.

<br>
### 3. Modify PAM configuration files to require the Yubikey.
This is the most delicate part of this tutorial, be sure to double check what you write because there's a high chance of getting locked out of your account(s) if you get sloppy. Before modifying the most important files we are going to test if the configuration has been done correctly. Fire up the terminal and write the following commands
```
sudo nano /etc/pam.d/screensaver
```

A CLI editor will show up, navigate to the line that says `auth       required       pam_opendirectory.so use_first_pass nullok` and add the following code on a newline
```
auth       required       /opt/local/lib/pam/pam_yubico.so mode=challenge-response
```
Save and exit (CTRL-O and then CTRL-X). In this way we have required the Yubikey only for unlocking the lockscreen of your laptop, now it's time to test it: remove the Yubikey, then lock the screen (either wait or press CTRL-CMD-Q) and try to login again <mark>WITHOUT</mark> inserting the Yubikey. If you didn't make any errors you should not be able to login. Now try inserting the Yubikey and logging in again, it should allow you in (remember to touch the Yubikey if you checked the "Require touch" option back in Step 1). 

If all worked flawlessly, fire up another terminal and spawn a root shell. Then go back to the other terminal and add the same line you added to `/etc/pam.d/screensaver` to `/etc/pam.d/authorization` and `/etc/pam.d/sudo`. Keep the root shell open, we will need it to edit the files in case something goes wrong.

Now, remove the Yubikey, open a third terminal and try first logging into the administrative account through `su <username>`. If it fails, good. Insert the Yubikey and try again, if it works it means you have successfully edited `/etc/pam.d/authorization`. Now remove the Yubikey and try from there `sudo su`. If it fails, good. Insert it again and run the command again, if it works it means that `/etc/pam.d/sudo` has been edited successfully too. You can now close the root shell.

<p class="alert alert-warning">
    <span class="label label-warning">CAUTION:</span> remember to go through this process again with a second Yubikey. The steps until the creation of <code>.yubico</code> included must not be repeated, only the <code>sudo ykpamcfg -2</code> and the following ones. Remember that the Yubikey will be required even for GUI authorization, when installing applications and editing system preferences for example.
</p>
<p class="alert alert-success">
    <span class="label label-success">SUCCESS:</span> you have successfully enabled 2FA for unlocking the screen, running <code>sudo</code> and logging in with users. 
</p>
<p class="alert alert-info">
    <span class="label label-info">NOTE:</span> for troubleshooting I suggest you head up to Yubico's official guide @ https://support.yubico.com/support/solutions/articles/15000015045-macos-logon-tool-configuration-guide
</p>
