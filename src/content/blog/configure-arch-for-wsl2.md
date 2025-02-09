---
author: Shivani Swaraj
pubDatetime: 2025-02-09T5:22:00Z
modDatetime: 2025-02-09T7:12:47.400Z
title: ArchWSL2 Installation and Usage Guide
slug: archwsl2-installation-and-usage-guide
featured: false
draft: false
tags:
  - wsl2
  - arch linux
  - installation
  - configuration
description:
  A comprehensive guide on installing, configuring, and using ArchWSL2 for an optimized Linux experience on Windows.
---

# ArchWSL2 Installation and Usage Guide

## Introduction
ArchWSL2 allows you to run Arch Linux on Windows Subsystem for Linux 2 (WSL2). It includes features such as increased virtual disk size, user setup, and systemd support.

## Important Information
ArchWSL2 may not properly load the Intel WSL driver by default, preventing the use of the D3D12 driver on Intel graphics cards. This occurs because Intel's WSL driver files link against libraries that do not exist in Arch Linux. To resolve this:

1. Identify missing libraries:
   ```sh
   ldd /usr/lib/wsl/drivers/iigd_dch_d.inf_amd64_49b17bc90a910771/*.so
   ```
2. Install missing libraries from the Arch Linux package repository.
3. If the correct library version is unavailable, create a symlink (e.g., linking `libedit.so.2` to `libedit.so.0.0.68`).

## Features
- Increased virtual disk size (default: 256GB).
- Creates and sets up a new user.
- Native systemd support for WSL v0.67.6+.
- Includes a `wsl.conf` file for configuration.

## Requirements
- **x64 systems:** Windows 10 Version 1903 (Build 18362) or higher.
- **ARM64 systems:** Windows 10 Version 2004 (Build 19041) or higher.
- **WSL2 not supported** on builds lower than 18362.

## Installation
1. **Enable WSL and Virtual Machine Platform** (for Windows 10 Version 2004 and lower):
   ```powershell
   dism.exe /online /enable-feature /featurename:Microsoft-Windows-Subsystem-Linux /all /norestart
   dism.exe /online /enable-feature /featurename:VirtualMachinePlatform /all /norestart
   ```
2. **Install WSL2 Kernel Update** ([Download here](https://aka.ms/wsl2kernel)).
3. **Set WSL2 as the default version**:
   ```powershell
   wsl --set-default-version 2
   ```
4. **Download and extract ArchWSL2**:
   - Download the latest release from [GitHub](https://github.com/sileshn/ArchWSL2/releases/tag/20250201).
   - Extract the files and place them in the desired directory.
   - Register the WSL instance:
     ```powershell
     Arch.exe
     ```

## Setup
1. Create a user during the first run, or manually create one:
   ```sh
   passwd
   useradd -m -g users -G wheel -s /bin/bash <username>
   echo "%wheel ALL=(ALL) ALL" >/etc/sudoers.d/wheel
   passwd <username>
   exit
   ```
2. Set the default user:
   ```sh
   sed -i '/\[user\]/a default = <username>' /etc/wsl.conf
   ```
   Restart WSL:
   ```powershell
   wsl --shutdown
   ```
   Or set the default user from Windows:
   ```powershell
   Arch.exe config --default-user <username>
   ```

## Usage
### Running ArchWSL2
```powershell
Arch.exe
```
### Running Commands
```powershell
Arch.exe run uname -r
```
```powershell
Arch.exe runp echo C:\Windows\System32\cmd.exe
```

### Configuration Options
```powershell
Arch.exe config --default-user <username>
Arch.exe config --default-term wt
```

## Updating ArchWSL2
To update Arch Linux:
```sh
sudo pacman -Syu
```
If updates fail:
```sh
sudo pacman -Syyuu
```

## Uninstalling ArchWSL2
```powershell
Arch.exe clean
```

## Backup and Restore
### Backup
```powershell
Arch.exe backup --tgz   # Exports to backup.tar.gz
Arch.exe backup --vhdxgz  # Exports to backup.ext4.vhdx.gz
```
### Restore
```powershell
Arch.exe install backup.tar.gz
```
```powershell
Arch.exe install backup.ext4.vhdx.gz
Arch.exe --default-uid 1000
```

## Building from Source
### Prerequisites
- Docker, tar, zip, unzip, bsdtar
- Git repository:
  ```sh
  git clone git@gitlab.com:sileshn/ArchWSL2.git
  cd ArchWSL2
  make
  ```
- Clean up:
  ```sh
  make clean
  ```

## Running Docker in ArchWSL2 Without Docker Desktop
```sh
sudo pacman -S docker
sudo systemctl start docker.service
sudo systemctl enable docker.service
sudo usermod -aG docker $USER
```

Now restart your WSL instance and start using Docker.
