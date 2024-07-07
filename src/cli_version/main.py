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
            print("\n Begin scan Crawler..\n")
            crawler()
            break
        elif input_choice == 2:
            print("\nBegin scan Csrf..\n")
            csrf_detector()
            break
        elif input_choice == 3:
            print("\nBegin scan Email card..\n")
            email_card_detect()
            break
        elif input_choice == 4:
            print("\nBegin scan File upload..\n")
            file_upload()
            break
        elif input_choice == 5:
            print("\Begin scan HTTP vulnerability")
            http_vulnerability()
        elif input_choice == 6:
            print("\nBegin scan LFI..\n")
            lfi_detect()
            break
        elif input_choice == 7:
            print("\nBegin scan OS command injection..\n")
            OS_command_injection()
            break
        elif input_choice == 8:
            print("\nBegin scan Path trasversal..\n")
            path_trasversal()
            break
        elif input_choice == 9:
            print("\nBegin scan Robot.txt..\n")
            robot_detect()
            break
        elif input_choice == 10:
            print("\nBegin Scan open ports..\n")
            scan_open_ports()
            break
        elif input_choice == 11:
            print("\nBegin Scan..\n")
            scan()
            break
        elif input_choice == 12:
            print("\nBegin scan SQLI XSS..\n")
            sqli_vuln_detect()
            break
        elif input_choice == 13:
            print("\nBegin scan SSRF..\n")
            ssrf_detect()
            break
        elif input_choice == 14:
            print("\nBegin scan SSL..\n")
            ssl_vuln_detect()
            break
        elif input_choice == 15:
            print("\nBegin scan SSTI..\n")
            SSTI_detect()
            break
        elif input_choice == 16:
            print("\nBegin scan Weak Authentication..\n")
            weak_auth_detect()
            break
        elif input_choice == 17:
            print("\nBegin scan WebSocket..\n")
            webSocket()
            break
        elif input_choice == 18:
            print("\nBegin scan WHOIS..\n")
            whois()
            break
        elif input_choice == 19:
            print("\nBegin scan XXE..\n")
            xxe_detect()
            break
        elif input_choice == 20:
            print("\nBegin scan CORS..\n")
            cors_detect()
            break
        elif input_choice == 21:
            print("\nBegin scan ALL..\n")
            all()
            break
        else:
            input = int(input("Key invalid. Choose another number: "))

def scan():
    scan.main()
    NewScan()

def cors_detect():
    NewScan()

def crawler():
    NewScan()

def csrf_detector():
    NewScan()

def email_card_detect():
    NewScan()

def file_upload():
    NewScan()

def http_vulnerability():
    NewScan()

def lfi_detect():
    NewScan()

def OS_command_injection():
    NewScan()

def path_trasversal():
    NewScan()

def robot_detect():
    NewScan()

def scan_open_ports():
    NewScan()

def sqli_xss_detect():
    NewScan()

def ssl_vuln_detect():
    NewScan()

def ssrf_detect():
    NewScan()

def SSTI_detect():
    NewScan()

def weak_auth_detect():
    NewScan()

def webSocket():
    NewScan()

def whois():
    NewScan()

def xxe_detect():
    NewScan()

def all():
    scan()
    cors_detect()
    crawler()
    csrf_detector()
    email_card_detect()
    file_upload()
    http_vulnerability()
    lfi_detect()
    OS_command_injection()
    path_trasversal()
    robot_detect()
    scan_open_ports()
    sqli_xss_detect()
    ssl_vuln_detect()
    ssrf_detect()
    STI_detect()
    weak_auth_detect()
    webSocket()
    whois()
    xxe_detect()


if __name__ == "__main__":
    BeginProgram()
