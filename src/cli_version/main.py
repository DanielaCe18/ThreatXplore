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
    print("2 - List Previous Scan")
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
            ListScan()
            break
        elif input_choice == 3:
            print("\nExiting the program...\n\n")
            EndProgram()
            break
        elif input_choice == 4:
            Help()
            break
        else:
            input_choice = int(input("Key invalid. Choose another number: "))

def NewScan():
    print("\n\n**$**$**$**$**$**$**$**$**$**$**$**$**$**$**")
    print("**$**$**$**$**$** NEW SCAN **$**$**$**$**$**")
    print("**$**$**$**$**$**$**$**$**$**$**$**$**$**$**\n\n")
    
    input_address = input("Enter the address of the website: ")

    while not input_address:
        input_address = input("Input invalid. Write a correct address: ")

    print("Scan ongoing ..")
    time.sleep(15)
    print("Scan finished. End of the program..")
    EndProgram()

def ListScan():
    print("List Previous Scan")
    EndProgram()



if __name__ == "__main__":
    BeginProgram()
