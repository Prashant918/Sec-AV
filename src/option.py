import sys
import os
from termcolor import colored
import random

def menu():
    print(colored("Here are the options:", 'green'))
    print(colored("1. Scan the System", 'yellow'))
    print(colored("2. Scan your Network", 'yellow'))
    print(colored("3. Analysis the file", 'yellow'))
    print(colored("4. Live Analyzer(GUI)", 'yellow'))
    print(colored("5. Got an Issues", 'yellow'))
    print(colored("6. Exit", 'yellow'))

def main():
    while True:
        menu()
        choice = input(colored("Enter your choice (1-6): ", 'cyan'))
        
        if choice == '1':
            print(colored("Scanning the system...", 'blue'))
            # Add your system scanning logic here
            
        elif choice == '2':
            print(colored("Scanning your network...", 'blue'))
            # Add your network scanning logic here
            
        elif choice == '3':
            print(colored("Analyzing the file...", 'blue'))
            filename = input(colored("Enter the file name to analyze: ", 'cyan'))
            if os.path.exists(filename):
                print(colored(f"File '{filename}' found. Analyzing...", 'green'))
                # Here you would add your file analysis logic
            else:
                print(colored(f"File '{filename}' not found.", 'red'))
                
        elif choice == '4':
            print(colored("Launching Live Analyzer (GUI)...", 'blue'))
            # Here you would add your GUI logic
            
        elif choice == '5':
            print(colored("If you have any issues, please contact support.", 'blue'))
            # Here you would add your issue reporting logic
            
        elif choice == '6':
            print(colored("Goodbye!", 'red'))
            break
            
        else:
            print(colored("Invalid option. Please try again.", 'red'))

if __name__ == "__main__":
    main()