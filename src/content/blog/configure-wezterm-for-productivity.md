---
author: Tanmay Panda
pubDatetime: 2025-02-09T12:00:00Z
title: Configuring WezTerm for Productivity
slug: configuring-wezterm-for-productivity
featured: true
draft: false
tags:
  - wezterm
  - productivity
  - terminal
  - configuration
description: A comprehensive guide on setting up and customizing WezTerm for an optimized terminal workflow.
---

Here are some recommendations, tips, and best practices for configuring `WezTerm` to enhance your terminal workflow.

## Table of contents

## What is WezTerm?

WezTerm is a GPU-accelerated terminal emulator that offers high performance and extensive customization options. It is designed to be fast, feature-rich, and highly configurable for power users.

## Installing WezTerm

To install `WezTerm`, follow the instructions based on your operating system:

### macOS

```sh
brew install --cask wezterm
```

### Linux

Download the latest `.deb` or `.rpm` package from the [official WezTerm releases](https://github.com/wez/wezterm/releases) and install it:

```sh
# Debian/Ubuntu
sudo dpkg -i wezterm*.deb

# Fedora
sudo rpm -i wezterm*.rpm
```

### Windows

Download and install the `.msi` package from the [WezTerm website](https://wezfurlong.org/wezterm/).

## Configuring WezTerm

The `wezterm.lua` configuration file allows you to customize your WezTerm experience. It is typically located at `~/.wezterm.lua`.

Below is a sample configuration:

```lua
-- wezterm.lua
local wezterm = require("wezterm")

config = wezterm.config_builder()

config = {
    automatically_reload_config = true,
    enable_tab_bar = false,
    window_close_confirmation = "NeverPrompt",
    window_decorations = "RESIZE",
    default_cursor_style = "SteadyBar",
    color_scheme = 'Catppuccin Mocha',
    font = wezterm.font("JetBrains Mono", {
        weight = "Bold"
    }),
    font_size = 14,

    -- WSL2 Ubuntu setup
    default_prog = {"wsl.exe", "--distribution", "Ubuntu", "--cd", "~"},
    window_padding = {
        left = 3,
        right = 3,
        top = 0,
        bottom = 0
    }
}

return config
```

## Key Features of This Configuration

- **Automatic Configuration Reload**: Changes to `wezterm.lua` are applied automatically.
- **Minimalist UI**: Hides the tab bar and uses minimal window decorations.
- **Custom Fonts and Colors**: Uses JetBrains Mono with the Catppuccin Mocha theme for a modern look.
- **WSL2 Support**: Sets WezTerm to start with WSL2 Ubuntu.
- **Padding Adjustments**: Fine-tuned padding for a balanced layout.

## Enhancing Productivity with WezTerm

### Multiplexing with tmux

WezTerm works well with `tmux`, allowing you to manage multiple terminal sessions efficiently. If you use `tmux`, ensure you configure WezTerm with:

```lua
config.keys = {
    {key = 't', mods = 'CTRL|SHIFT', action = wezterm.action({SpawnTab = "CurrentPaneDomain"})},
}
```

This allows you to open new tabs with `Ctrl + Shift + T`.

## Conclusion

WezTerm is a powerful terminal emulator that, when customized, can significantly improve your workflow. By tweaking the configuration file, you can create an optimized terminal experience tailored to your needs.
