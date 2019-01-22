---
layout: post
published: true
title: 'Securing Your Macbook Part 1: Separating Privileges'
---
# Introduction

This is a blogpost serie on how I keep my Macbook ~~in~~secure. These posts take a lot from the following resources so kudos to them first:

- [MacOS Security and Privacy Guide ](https://github.com/drduh/macOS-Security-and-Privacy-Guide)
- [Configuring MacOS Sierra to authenticate with YubiKey 4](https://medium.com/@ellenbeldner/configuring-macos-sierra-to-authenticate-with-yubikey-4-876a8ab81e07)

The idea behind this is to make it ~~impossible~~ very difficult for an attacker to take control of your device even with physical access. Now, impossible is nothing, and that's even more true in the security industry. </mark>Always expect an attacker to be able to fully compromise your device with physical access</mark>, it's just a matter of time. That does not mean you have to make it easier for him to compromise you: the more time you buy, the less likely the information he will retrieve will be of any use.

In this first part we are going to take a look at privilege separation in macOS (I will be using macOS 10.14 Mojave but the same principles theoretically apply for the other versions). The idea is to have separate accounts for separate "privilege levels" and by that I mean having AT LEAST two accounts and AT BEST three accounts: one for administrative purposes which can use `sudo`, one for everyday tasks and one capable of decrypting FileVault2 (you do encrypt your laptop, right?).


<p class="alert alert-warning">
    <span class="label label-warning">CAUTION:</span> be very careful, especially in the part where we will be giving FV2 decryption capabilities to just one account. If you manage to lose the decryption password or something bad happens you better have backups. In case you didn't figure it out by yourself, I take no responsibility if you f\*\*k up your machine :)
</p>

## Different passwords for FV2 decryption and user authentication




