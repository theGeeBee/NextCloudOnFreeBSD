#!/bin/sh

ifconfig | sed -n '/.inet /{s///;s/ .*//;p;}'