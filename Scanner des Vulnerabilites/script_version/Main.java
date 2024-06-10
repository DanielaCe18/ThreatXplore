import java.util.Scanner;

public class Main {
    public static void main(String[] args) {
        BeginProgram();
        System.exit(0);
    }

    public static void BeginProgram(){
        System.out.println("******************************************************************************************************************");
        System.out.println("******************************************************************************************************************");
        System.out.println("      *******  ####         ####  #####   #####  #####      ########  ########   ########  ########  *******      ");
        System.out.println("     *******    ##           ##    ###     ###    ###        ##        ##  ###    ##        ##        *******     ");
        System.out.println("                 ##         ##     ###     ###    ###        #####     ## ###     ##        ##                    ");
        System.out.println("    *******       ##       ##      ###     ###    ###        ##        #####      ####      ####       *******    ");
        System.out.println("                   ##     ##       ###     ###    ###        ##        ## ###     ##        ##                    ");
        System.out.println("     *******        ##   ##        ###     ###    ###        ##        ##  ###    ##        ##        *******     ");
        System.out.println("      *******        #####         ###########    ########  ####      ####  ###  ########  ########  *******      ");
        System.out.println("******************************************************************************************************************");
        System.out.println("******************************************************************************************************************\n\n\n");

        MainMenu();
    }


    public static void EndProgram(){
        System.out.println("**********************************************************");
        System.out.println("**********************************************************");
        System.out.println("      ******* #######  ##       ##  ######  *******       ");
        System.out.println("     *******  ##       ## ##    ##    ##  ##  *******     ");
        System.out.println("              ##       ##  ##   ##    ##   ##             ");
        System.out.println("    *******   ####     ##   ##  ##    ##    ## *******    ");
        System.out.println("              ##       ##    ## ##    ##   ##             ");
        System.out.println("     *******  ##       ##     ####    ##  ##  *******     ");
        System.err.println("      ******* ######   ##      ##   ######   *******      ");
        System.out.println("**********************************************************");
        System.out.println("**********************************************************\n\n\n");
        System.exit(0);
    }

    public static void MainMenu(){
        Scanner scanner = new Scanner(System.in);
        int choice;

        System.out.println("                        Welcome to Main Menu                            ");
        System.out.println("*$*$*$*$*$*$*$*$*$*$*$*$*$*$*$*$*$*$*$*$*$*$*$*$*$*$*$*$*$*$*$*$*$*$*$*$");
        System.out.println("*$*$*$*$*$*$*$*$*$*$*$*$*$*$ Main Menu *$*$*$*$*$*$*$*$*$*$*$*$*$*$*$*$*");
        System.out.println("1 - Learn More");
        System.out.println("2 - Scan");
        System.out.println("3 - Quit");
        System.out.println("4 - Help");
        System.out.println("*$*$*$*$*$*$*$*$*$*$*$*$*$*$*$*$*$*$*$*$*$*$*$*$*$*$*$*$*$*$*$*$*$*$*$*$");
        System.out.println("*$*$*$*$*$*$*$*$*$*$*$*$*$*$*$*$*$*$*$*$*$*$*$*$*$*$*$*$*$*$*$*$*$*$*$*$\n\n");

        System.out.print("Make a choice : ");
        choice = scanner.nextInt();

        boolean state = false;
        while (!state) {
            switch (choice) {
                case 1:
                    state = true;
                    scanner.close();
                    LearnMore();
                    break;
                case 2:
                    state = true;
                    scanner.close();
                    MenuScan();
                    break;
                case 3:
                    state = true;
                    scanner.close();
                    System.out.println("\nExiting the program...\n\n");
                    EndProgram();
                    break;
                case 4:
                    scanner.close();
                    Help();
                    break;
                default:
                    System.out.println("Key invalid. Choose another number :");
                    break;
            }   
        }

    }

    public static void Help(){
        System.out.println("Opening Help");

        EndProgram();
    }

    public static void LearnMore(){
        System.out.println("To Learn More");

        EndProgram();
    }

    public static void MenuScan(){
        Scanner scanner = new Scanner(System.in);
        int choice;

        System.out.println("\n\n                    Welcome to Menu Scan");
        System.out.println("*$*$*$*$*$*$*$*$*$*$*$*$*$*$*$*$*$*$*$*$*$*$*$*$*$*$*$*$*$*$*$*$*$*$*$*$");
        System.out.println("*$*$*$*$*$*$*$*$*$*$*$*$*$*$ SCAN*$*$*$*$*$*$*$*$*$*$*$*$*$*$");
        System.out.println("1 - New Scan");
        System.out.println("2 - List Previous Scan");
        System.out.println("3 - Main Menu");
        System.out.println("4 - Quit");
        System.out.println("5 - Help");
        System.out.println("*$*$*$*$*$*$*$*$*$*$*$*$*$*$*$*$*$*$*$*$*$*$*$*$*$*$*$*$*$*$*$*$*$*$*$*$");
        System.out.println("*$*$*$*$*$*$*$*$*$*$*$*$*$*$*$*$*$*$*$*$*$*$*$*$*$*$*$*$*$*$*$*$*$*$*$*$\n\n");

        System.out.print("Make a choice : ");
        choice = scanner.nextInt();

        boolean state = false;
        while (!state) {
            switch (choice) {
                case 1:
                    state = true;
                    scanner.close();
                    NewScan();
                    break;
                case 2:
                    state = true;
                    scanner.close();
                    ListScan();
                    break;
                case 3:
                    state = true;
                    scanner.close();
                    System.out.println("\nExiting the program...\n\n");
                    EndProgram();
                    break;
                case 4:
                    scanner.close();
                    Help();
                    break;
                default:
                    System.out.println("Key invalid. Choose another number :");
                    break;
            }   
        }
    }

    public static void NewScan(){
        System.out.println("**$**$**$**$**$**$**$**$**$**$**$**$**$**$**");
        System.out.println("**$**$**$**$**$** NEW SCAN **$**$**$**$**$**");
        System.out.println("**$**$**$**$**$**$**$**$**$**$**$**$**$**$**");
        
        EndProgram();
    }

    public static void ListScan(){
        System.out.println("List Previous Scan");

        EndProgram();
    }

}
