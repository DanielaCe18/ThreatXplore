package older_version;
import java.util.Scanner;

public class MenuProgram {

    public static void main(String[] args) {
        Scanner scanner = new Scanner(System.in);
        int choice;

        do {
            System.out.println("Main Menu");
            System.out.println("1. Option 1");
            System.out.println("2. Option 2");
            System.out.println("3. Option 3");
            System.out.println("4. Exit");
            System.out.print("Enter your choice: ");
            choice = scanner.nextInt();

            switch (choice) {
                case 1:
                    option1();
                    break;
                case 2:
                    option2();
                    break;
                case 3:
                    option3();
                    break;
                case 4:
                    System.out.println("Exiting the program.");
                    break;
                default:
                    System.out.println("Invalid choice. Please choose a number between 1 and 4.");
            }
        } while (choice != 4);

        scanner.close();
    }

    public static void option1() {
        System.out.println("You selected Option 1.");
        // Add more functionality here
    }

    public static void option2() {
        System.out.println("You selected Option 2.");
        // Add more functionality here
    }

    public static void option3() {
        System.out.println("You selected Option 3.");
        // Add more functionality here
    }
}
