---
author: Tanmay Panda
pubDatetime: 2025-02-26T2:11:23Z
title: Setting Up FortiClient VPN in WSL2
slug: setting-up-forticlient-vpn-wsl2
featured: false
draft: false
tags:
  - WSL2
  - VPN
  - FortiClient
  - OpenFortiVPN
  - Networking
description: A complete guide to setting up FortiClient VPN in WSL2 using OpenFortiVPN, so you can access internal resources seamlessly from your Linux environment.
---

# Setting Up FortiClient VPN in WSL2

## Introduction

So, you’ve got **WSL2** up and running, but your company’s **FortiClient VPN** is giving you a headache? WSL2’s networking quirks make it a bit tricky, but don’t worry—I’ve got you covered! 🎩✨

In this guide, we’ll use **OpenFortiVPN**, an open-source alternative to FortiClient, to get your WSL2 environment connected to your company’s network like a pro. Let’s dive in! 🏊‍♂️

---

## Table of Contents

---

## Step 1: Install OpenFortiVPN in WSL2

First, let’s install **OpenFortiVPN** so we can connect to the FortiClient VPN from WSL2.

### 1.1 Update Your System

```bash
sudo apt update && sudo apt upgrade -y
```

### 1.2 Install OpenFortiVPN

```bash
sudo apt install openfortivpn -y
```

Verify the installation:

```bash
openfortivpn --version
```

If you see the version number, congrats! 🎉

---

## Step 2: Configure OpenFortiVPN

Next, we need to configure OpenFortiVPN with your company’s details.

### 2.1 Create a Configuration File

```bash
sudo vi /etc/openfortivpn/config
```

Add the following details (replace with your actual VPN credentials):

```ini
host = vpn.example.com
port = 443
username = your_username
password = your_password
```

_Save and exit (`ESC`, then `:wq` in vi)._

### 2.2 Secure the Configuration File

```bash
sudo chmod 600 /etc/openfortivpn/config
```

---

## Step 3: Start the VPN Connection

Now, let’s fire up the VPN! 🚀

```bash
sudo openfortivpn
```

If all goes well, you should see a **successful connection message**. 🎉

---

## Step 4: Allow WSL2 to Use the VPN

By default, WSL2 doesn’t route traffic through the VPN. Let’s fix that!

### 4.1 Identify Your VPN Interface

Run:

```bash
ip a | grep ppp
```

This should return something like `ppp0`. Note this name.

### 4.2 Add a Route for WSL2 Traffic

Find the VPN’s **gateway IP**:

```bash
ip route | grep default
```

Then add a route:

```bash
sudo ip route add 0.0.0.0/0 dev ppp0
```

To verify:

```bash
ip route show
```

---

## Step 5: Persist the VPN Connection

So you don’t have to manually start the VPN every time, let’s make it persistent. 🔄

### 5.1 Create a systemd Service (if using systemd in WSL2)

```bash
sudo vi /etc/systemd/system/openfortivpn.service
```

Add:

```ini
[Unit]
Description=FortiClient VPN Connection
After=network.target

[Service]
ExecStart=/usr/bin/openfortivpn
Restart=always

[Install]
WantedBy=default.target
```

Enable and start:

```bash
sudo systemctl enable openfortivpn
sudo systemctl start openfortivpn
```

### 5.2 Add to `.bashrc` or `.zshrc`

```bash
echo "sudo openfortivpn &" >> ~/.bashrc
```

---

## Step 6: Test VPN Access in WSL2

Check your public IP to confirm you’re connected:

```bash
curl ifconfig.me
```

If it shows your **VPN’s IP**, you’re good to go! ✅

---

## Step 7: Using DBeaver with WSL2 VPN

If you use **DBeaver** for database work and need it to route through the VPN:

1. Open **DBeaver**
2. Go to **Connection Settings** → **Proxy**
3. Enable **SOCKS Proxy**
4. Set:
   - **Host:** `localhost`
   - **Port:** `1080`
5. Start a SOCKS proxy in WSL2:

```bash
ssh -D 1080 -q -C -N user@localhost
```

Now, DBeaver will tunnel through your VPN! 🚀

---

## Conclusion

Congratulations! 🎉 You’ve successfully set up **FortiClient VPN in WSL2** using **OpenFortiVPN**. Now, your **Linux environment** can securely access internal resources, and Windows apps like **DBeaver** can route through the VPN as well.

Happy coding, and may your VPN never disconnect at the worst time! 😆🔥
