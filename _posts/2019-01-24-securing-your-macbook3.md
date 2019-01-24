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
    <span class="label label-info">NOTE:</span> it's possible to use the Yubikey as a smart card with a pin for user login instead of the password. While some use it that way I don't think it's a good idea as the pin is at best a 8 characters long number, I think it's better to use a strong password and the Yubikey as a physical token.
</p>

