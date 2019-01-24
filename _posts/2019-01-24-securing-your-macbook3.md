---
layout: post
published: true
image: /img/IMG_6264.jpg
date: '2019-01-24'
title: Securing Your Macbook Part 3
subtitle: '2FA at login: using Yubikeys as a second authentication layer'
---
# Introduction
Quick recap of what we saw in the [first](https://blog.notso.pro/2019-01-21-securing-your-macbook/) and [second](https://blog.notso.pro/2019-01-23-securing-your-macbook2/) parts of this serie. We started out by seeing how to setup your Macbook so that only one account is allowed to decrypt FileVault2, effectively creating two different passwords for mass storage decryption and user login authentication. After that we saw how to further compartmentalize by creating an account with administrative privileges, used only for administrative tasks like installing new software, adding new accounts or changing system preferences, and demoting our own user to standard account in order to make it harder for an attacker that has comprimised it to escalate privileges and gain full control of the device.

In this part of the serie we will see how to use a [Yubikey](https://www.yubico.com/) to obtain a form of [two factor authentication (2FA)](https://en.wikipedia.org/wiki/Multi-factor_authentication) at user login. The end result will be that to access your account you will have to provide your password and have the Yubikey inserted in your laptop. This measure can be also applied to secure the use of the command `sudo`.

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
First things first, we need the right software. We will install the [Yubikey Manager](https://www.yubico.com/products/services-software/download/yubikey-manager/) tool by Yubico and the Yubikey module for Pluggable Authentication Modules (PAM). The first can be downloaded by the link provided above and installed through the GUI while the second requires the installation through [MacPorts](https://www.macports.org/).
<p class="alert alert-info">
    <span class="label label-info">NOTE:</span> if you haven't installed MacPorts yet go to the link and install it. I've had a bad experience on Mojave using brew to install the yubico-pam module so I suggest you use MacPorts.
</p>
To install the module needed to interface the Yubikey with PAM we will run the following command:
```
sudo port install yubico-pam
```
We have got all the software we need, now we will proceed to setup the Yubikey. It can be done via the CLI but I think using Yubikey Manager is a bit more intuitive.

Open up Yubikey Manager, click on <mark>Applications</mark> and select <mark>OTP</mark>. Where it says <mark>Long Touch (Slot 2)</mark> click <mark>Configure</mark>. Select <mark>Challenge-response</mark> and click <mark>Next</mark>. Now click <mark>Generate</mark> in order to generate a new secret that will be stored on your Yubikey. Optionally you can select <mark>Require touch</mark> if you want your Yubikey to be triggered and answer the challenge only if you touch the button on it.

<br>
### 2. Setup the challenge-response for every account


