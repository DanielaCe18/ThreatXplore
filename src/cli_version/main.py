# cli/test.py

import sys
import os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../scripts')))

import scan

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
    print("22 - Return")
    print("23 - QUIT")
    print("**$**$**$**$**$**$**$**$**$**$**$**$**$**$**")
    print("**$**$**$**$**$**$**$**$**$**$**$**$**$**$**\n\n")

    print("Scan ongoing ..")
    
    print("Scan finished. End of the program..")
    EndProgram()

def ListScan():
    print("List Previous Scan")
    EndProgram()


def scan():
    scan.main()
    NewScan()

def cors_detect():
    pass

def crawlerFile():
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
