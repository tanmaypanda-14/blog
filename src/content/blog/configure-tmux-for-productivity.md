---
author: Tanmay Panda
pubDatetime: 2022-09-23T15:22:00Z
modDatetime: 2023-12-21T09:12:47.400Z
title: Configuring tmux for Productivity
slug: configuring-tmux-for-productivity
featured: true
draft: false
tags:
  - tmux
  - productivity
  - terminal
  - configuration
description:
  A comprehensive guide on setting up and customizing tmux for an optimized terminal
  workflow.
---

Here are some recommendations, tips, and best practices for configuring `tmux` to enhance your terminal workflow.

## Table of contents

## What is tmux?

`tmux` (terminal multiplexer) is a powerful tool that allows users to manage multiple terminal sessions within a single window. It is particularly useful for developers, sysadmins, and anyone who works extensively in the command line.

## Installing tmux

To install `tmux`, run the following commands based on your operating system:

```sh
# Debian/Ubuntu
sudo apt install tmux

# macOS (via Homebrew)
brew install tmux

# Arch Linux
sudo pacman -S tmux

# Fedora
sudo dnf install tmux
```

## Basic tmux Commands

Before diving into configuration, here are some essential `tmux` commands:

| Command                     | Description                              |
| --------------------------- | ---------------------------------------- |
| `tmux`                      | Start a new tmux session                 |
| `tmux new -s name`          | Start a new session with a specific name |
| `tmux ls`                   | List active sessions                     |
| `tmux attach -t name`       | Attach to an existing session            |
| `tmux detach`               | Detach from a session                    |
| `tmux kill-session -t name` | Kill a specific session                  |

## Configuring tmux

The `~/.tmux.conf` file allows you to customize your `tmux` experience. Below is a sample configuration:

```sh
# Enable true color support
set-option -sa terminal-overrides ",xterm*:Tc"

# Enable mouse support
set -g mouse on

# Change prefix key from Ctrl-b to Ctrl-Space
unbind C-b
set -g prefix C-Space
bind C-Space send-prefix

# Vim-style pane navigation
bind h select-pane -L
bind j select-pane -D
bind k select-pane -U
bind l select-pane -R

# Start windows and panes at 1, not 0
set -g base-index 1
set -g pane-base-index 1
set-window-option -g pane-base-index 1
set-option -g renumber-windows on

# Use Alt-arrow keys without prefix to switch panes
bind -n M-Left select-pane -L
bind -n M-Right select-pane -R
bind -n M-Up select-pane -U
bind -n M-Down select-pane -D

# Shift arrow to switch windows
bind -n S-Left previous-window
bind -n S-Right next-window

# Shift + Alt + Vim keys to switch windows
bind -n M-H previous-window
bind -n M-L next-window

# Set color theme
set -g @catppuccin_flavour 'mocha'

# Plugin management
set -g @plugin 'tmux-plugins/tpm'
set -g @plugin 'tmux-plugins/tmux-sensible'
set -g @plugin 'christoomey/vim-tmux-navigator'
set -g @plugin 'dreamsofcode-io/catppuccin-tmux'
set -g @plugin 'tmux-plugins/tmux-yank'
set -g @plugin 'jaclu/tmux-menus'
set -g @plugin 'tmux-plugins/tmux-sidebar'
set -g @plugin 'tmux-plugins/tmux-resurrect'
set -g @plugin 'tmux-plugins/tmux-continuum'

run '~/.tmux/plugins/tpm/tpm'

# Auto-save and restore sessions
set -g @continuum-restore 'on'

# Enable vi mode
set-window-option -g mode-keys vi
bind-key -T copy-mode-vi v send-keys -X begin-selection
bind-key -T copy-mode-vi C-v send-keys -X rectangle-toggle
bind-key -T copy-mode-vi y send-keys -X copy-selection-and-cancel

# Splitting windows with current path
bind '"' split-window -v -c "#{pane_current_path}"
bind % split-window -h -c "#{pane_current_path}"
```

## Splitting Windows and Navigating Panes

| Shortcut         | Description             |
| ---------------- | ----------------------- |
| `Ctrl-Space "`   | Split pane horizontally |
| `Ctrl-Space %`   | Split pane vertically   |
| `Alt + Arrow`    | Move between panes      |
| `Shift + Arrow`  | Switch between windows  |
| `Ctrl-Space x`   | Close the current pane  |

## Plugins for tmux

Using the `tmux` plugin manager (`tpm`), you can enhance your `tmux` experience. First, install `tpm`:

```sh
git clone https://github.com/tmux-plugins/tpm ~/.tmux/plugins/tpm
```

Then, add the following to your `~/.tmux.conf`:

```sh
set -g @plugin 'tmux-plugins/tpm'
set -g @plugin 'tmux-plugins/tmux-resurrect'
set -g @plugin 'tmux-plugins/tmux-sensible'
run '~/.tmux/plugins/tpm/tpm'
```

Reload `tmux` and press `Ctrl-Space I` to install the plugins.

## Conclusion

By customizing `tmux`, you can greatly improve your productivity and workflow within the terminal. Experiment with different settings and plugins to create an optimal setup that works for you.

