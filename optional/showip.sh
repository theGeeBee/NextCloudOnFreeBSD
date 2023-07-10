#!/bin/sh

### Show available IP addresses on your system
### Maybe use this in future to auto-generate IP of Jail/VM (?)
ifconfig | sed -n '/.inet /{s///;s/ .*//;p;}' | head -1