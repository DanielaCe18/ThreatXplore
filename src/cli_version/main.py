# cli/test.py

import sys
import os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../scripts')))

import importlib

import scan
import crawler
import cors_detect
import csrf_detector

email_card_detect = importlib.import_module("email-card_detect")
import email_card_detect

import file_upload

http_vulnerabilities = importlib.import_module("http-vulnerabilities")
import http_vulnerabilities

import lfi_detect
import OS_command_injection
import path_trasversal
import robot_detect

scan_open_ports = importlib.import_module("scan-open-ports")
import scan_open_ports

sqli_vuln_detect = importlib.import_module("sqli-vuln_detect")
import sqli_vuln_detect

ssl_vuln_detect = importlib.import_module("ssl-vuln_detect")
import ssl_vuln_detect

import ssrf_detect
import SSTI_detect

weak_auth_detect = importlib.import_module("weak-auth_detect")
import weak_auth_detect
import WebSocket
import whois
import xxe_detect

import time



def BeginProgram():
    print("**************************************************************************************************************************************************************")
    print("**************************************************************************************************************************************************************")
    print("      *******  #######  ##    ##  #######   #######         ##          ######  #####    #####   #######  ##       ########  #######   #######  *******       ")
    print("     *******      ##    ##    ##  ##   ##   ##             ####           ##      ##      ##     ##   ##  ##       ##    ##  ##   ##   ##         *******     ")
    print("                  ##    ##    ##  ##  ##    ##            ##  ##          ##        ##  ##       ##  ##   ##       ##    ##  ##  ##    ##                     ")
    print("    *******       ##    ########  #####     #####        ########         ##          ##         #####    ##       ##    ##  #####     #####       *******    ")
    print("                  ##    ##    ##  ##  ##    ##          ##      ##        ##        ##  ##       ##       ##       ##    ##  ##  ##    ##                     ")
    print("     *******      ##    ##    ##  ##   ##   ##         ##        ##       ##      ##      ##     ##       ##       ##    ##  ##   ##   ##         *******     ")
    print("      *******     ##    ##    ##  ##    ##  #######  #####      #####     ##    #####    #####  ####      #######  ########  ##    ##  #######  *******       ")
    print("************************************************Less Vulnerability, More Security*****************************************************************************")
    print("**************************************************************************************************************************************************************")
    print("**************************************************************************************************************************************************************\n\n\n")

    MainMenu()


def EndProgram():
    print("**********************************************************")
    print("**********************************************************")
    print("      ******* #######  ##       ##  ######  *******       ")
    print("     *******  ##       ## ##    ##    ##  ##  *******     ")
    print("              ##       ##  ##   ##    ##   ##             ")
    print("    *******   ####     ##   ##  ##    ##    ## *******    ")
    print("              ##       ##    ## ##    ##   ##             ")
    print("     *******  ##       ##     ####    ##  ##  *******     ")
    print("      ******* ######   ##      ##   ######   *******      ")
    print("**********************************************************")
    print("**********************************************************\n\n\n")
    exit(0)

def MainMenu():
    print("                        Welcome to Main Menu                            ")
    print("*$*$*$*$*$*$*$*$*$*$*$*$*$*$*$*$*$*$*$*$*$*$*$*$*$*$*$*$*$*$*$*$*$*$*$*$")
    print("*$*$*$*$*$*$*$*$*$*$*$*$*$*$ Main Menu *$*$*$*$*$*$*$*$*$*$*$*$*$*$*$*$*")
    print("1 - Learn More")
    print("2 - Scan")
    print("3 - Quit")
    print("4 - Help")
    print("*$*$*$*$*$*$*$*$*$*$*$*$*$*$*$*$*$*$*$*$*$*$*$*$*$*$*$*$*$*$*$*$*$*$*$*$")
    print("*$*$*$*$*$*$*$*$*$*$*$*$*$*$*$*$*$*$*$*$*$*$*$*$*$*$*$*$*$*$*$*$*$*$*$*$\n\n")

    choice = int(input("Make a choice: "))

    while True:
        if choice == 1:
            LearnMore()
            break
        elif choice == 2:
            MenuScan()
            break
        elif choice == 3:
            print("\nExiting the program...\n\n")
            EndProgram()
            break
        elif choice == 4:
            Help()
            break
        else:
            choice = int(input("Key invalid. Choose another number: "))

def Help():
    print("Opening Help")
    EndProgram()

def LearnMore():
    print("To Learn More")
    EndProgram()

def MenuScan():
    print("\n\n                    Welcome to Menu Scan")
    print("*$*$*$*$*$*$*$*$*$*$*$*$*$*$*$*$*$*$*$*$*$*$*$*$*$*$*$*$*$*$*$*$*$*$*$*$")
    print("*$*$*$*$*$*$*$*$*$*$*$*$*$*$ SCAN*$*$*$*$*$*$*$*$*$*$*$*$*$*$")
    print("1 - New Scan")
    print("3 - Main Menu")
    print("4 - Quit")
    print("5 - Help")
    print("*$*$*$*$*$*$*$*$*$*$*$*$*$*$*$*$*$*$*$*$*$*$*$*$*$*$*$*$*$*$*$*$*$*$*$*$")
    print("*$*$*$*$*$*$*$*$*$*$*$*$*$*$*$*$*$*$*$*$*$*$*$*$*$*$*$*$*$*$*$*$*$*$*$*$\n\n")

    input_choice = int(input("Make a choice: "))

    while True:
        if input_choice == 1:
            NewScan()
            break
        elif input_choice == 2:
            print("\nExiting the program...\n\n")
            EndProgram()
            break
        elif input_choice == 3:
            Help()
            break
        else:
            input_choice = int(input("Key invalid. Choose another number: "))

def NewScan():
    print("\n\n**$**$**$**$**$**$**$**$**$**$**$**$**$**$**")
    print("**$**$**$**$**$** NEW SCAN **$**$**$**$**$**")
    print("Choose the scan you want to realize:")
    print("1 - Crawler")
    print("2 - Csrf")
    print("3 - Email card")
    print("4 - File upload")
    print("5 - Http vulnerability")
    print("6 - LFI")
    print("7 - OS command injection")
    print("8 - Path trasversal")
    print("9 - Robot.txt")
    print("10 - Scan open ports")
    print("11 - Scan")
    print("12 - SQLI XSS")
    print("13 - SSRF")
    print("14 - SSL")
    print("15 - SSTI")
    print("16 - Weak Authentication")
    print("17 - WebSocket")
    print("18 - WHOIS")
    print("19 - XXE")
    print("20 - CORS")
    print("21 - ALL")
    print("22 - Accueil")
    print("23 - QUIT")
    print("**$**$**$**$**$**$**$**$**$**$**$**$**$**$**")
    print("**$**$**$**$**$**$**$**$**$**$**$**$**$**$**\n\n")

    print("Scan ongoing ..")
    
    while True:
        if input_choice == 1:
            crawler()
            break
        elif input_choice == 2:
            print("\nExiting the program...\n\n")
            EndProgram()
            break
        elif input_choice == 3:
            print("\nExiting the program...\n\n")
            EndProgram()
            break
        elif input_choice == 4:
            print("\nExiting the program...\n\n")
            EndProgram()
            break
        elif input_choice == 5:
            print("\nExiting the program...\n\n")
            EndProgram()
            break
        elif input_choice == 6:
            Help()
            break
        elif input_choice == 7:
            Help()
            break
        elif input_choice == 8:
            Help()
            break
        elif input_choice == 9:
            Help()
            break
        elif input_choice == 10:
            Help()
            break
        elif input_choice == 11:
            Help()
            break
        elif input_choice == 12:
            Help()
            break
        elif input_choice == 13:
            Help()
            break
        elif input_choice == 14:
            Help()
            break
        elif input_choice == 15:
            Help()
            break
        elif input_choice == 16:
            Help()
            break
        elif input_choice == 17:
            Help()
            break
        elif input_choice == 18:
            Help()
            break
        elif input_choice == 19:
            Help()
            break
        elif input_choice == 20:
            Help()
            break
        elif input_choice == 21:
            Help()
            break
        elif input_choice == 22:
            Help()
            break
        elif input_choice == 23:
            EndProgram()
            break
        else:
            input_choice = int(input("Key invalid. Choose another number: "))



def ListScan():
    print("List Previous Scan")
    EndProgram()

def scan():
    scan.main()
    NewScan()

def cors_detect():
    pass

def crawler():
    pass

def csrf_detector():
    pass

def email_card_detect():
    pass

def file_upload():
    pass

def http_vulnerability():
    pass

def lfi_detect():
    pass

def OS_command_injection():
    pass

def path_trasversal():
    pass

def robot_detect():
    pass

def scan_open_ports():
    pass

def sqli_xss_detect():
    pass

def ssl_vuln_detect():
    pass

def SSTI_detect():
    pass

def weak_auth_detect():
    pass

def WebSocket():
    pass

def whois():
    pass

def xxe_detect():
    pass

def all():
    pass


if __name__ == "__main__":
    BeginProgram()
