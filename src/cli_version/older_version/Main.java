package older_version;
import java.util.Scanner;

public class Main {
    private static final Scanner sc = new Scanner(System.in);
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
        choice = sc.nextInt();

        boolean state = false;
        while (!state) {
            switch (choice) {
                case 1:
                    state = true;
                    LearnMore();
                    break;
                case 2:
                    state = true;
                    MenuScan();
                    break;
                case 3:
                    state = true;
                    System.out.println("\nExiting the program...\n\n");
                    EndProgram();
                    break;
                case 4:
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
        int input;

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
        input = sc.nextInt();

        boolean state = false;
        while (!state) {
            switch (input) {
                case 1:
                    state = true;
                    NewScan();
                    break;
                case 2:
                    state = true;
                    ListScan();
                    break;
                case 3:
                    state = true;
                    System.out.println("\nExiting the program...\n\n");
                    EndProgram();
                    break;
                case 4:
                    Help();
                    break;
                default:
                    System.out.println("Key invalid. Choose another number :");
                    break;
            }   
        }
    }

    public static void NewScan(){
        try {
            String input;
            System.out.println("\n\n**$**$**$**$**$**$**$**$**$**$**$**$**$**$**");
            System.out.println("**$**$**$**$**$** NEW SCAN **$**$**$**$**$**");
            System.out.println("**$**$**$**$**$**$**$**$**$**$**$**$**$**$**\n\n");
        
            System.out.println("Enter the address of the website : ");
            input = sc.nextLine();

            while (input.isEmpty()) {
                System.out.println("Input invalid. Write a correct address : ");
            }    

                System.out.println("Scan ongoing ..");
            
                Thread.sleep(15000);
            
                System.out.println("Scan finished. End of the program..");

                EndProgram();
            
            } catch (InterruptedException e) {
                // TODO Auto-generated catch block
                e.printStackTrace();
            }
        }

        public static void ListScan(){
            System.out.println("List Previous Scan");

            EndProgram();
        }

}
