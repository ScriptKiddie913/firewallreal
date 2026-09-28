#!/usr/bin/env python3
"""Launcher: python3 sfwctl.py <command>   (see --help)"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from sentinelfw.cli import main  # noqa: E402

main()
