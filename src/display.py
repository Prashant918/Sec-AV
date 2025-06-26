import pyfiglet
from termcolor import colored
import random
import time

# Colors to choose from
colors = ['red', 'green', 'yellow', 'blue', 'magenta', 'cyan', 'white', 'grey', 
          'bright_red', 'bright_green', 'bright_yellow', 'bright_blue', 'bright_magenta', 'bright_cyan', 
          'bright_white']

# Fonts to choose from
fonts = ['slant', 'big', 'block', 'bubble', 'digital', 'isometric1', 'letters', 'alligator', 
         'banner3-D', 'doh', 'epic', 'fuzzy', 'larry3d', 'lean', 'mini', 'script', 'standard']

# Cybersecurity related messages
security_messages = [
    "Stay Safe Online!",
    "Protect Your Data",
    "Security First",
    "Cyber Vigilance",
    "Digital Defense",
    "Secure Computing",
    "Privacy Matters",
    "Trust but Verify"
]

def greet():
    # Get username from system
    username = os.getenv('USER') or os.getenv('USERNAME') or 'User'
    print(colored(f"Hello, {username}! Hope you're having a great day!", 'blue'))
    print()

def display_banner(text="Prashant918", font=None, color=None):
    """Display a colorful ASCII art banner"""
    if font is None:
        font = random.choice(fonts)
    if color is None:
        color = random.choice(colors)
    
    try:
        ascii_art = pyfiglet.figlet_format(text, font=font)
        print(colored(ascii_art, color))
    except Exception as e:
        # Fallback to simple text if font is not available
        print(colored(f"\n=== {text} ===\n", color))

def display_welcome():
    """Display welcome message with banner"""
    display_banner("Prashant918")
    print(colored("Welcome to Prashant918 - Cybersecurity File Analysis Tool", 'cyan'))
    print(colored("=" * 60, 'cyan'))
    
def display_random_message():
    """Display a random cybersecurity message"""
    message = random.choice(security_messages)
    color = random.choice(colors)
    font = random.choice(fonts)
    
    try:
        ascii_message = pyfiglet.figlet_format(message, font=font)
        print(colored(ascii_message, color))
    except Exception:
        print(colored(f"\n*** {message} ***\n", color))

def display_loading(duration=2):
    """Display a loading animation"""
    print(colored("Analyzing file", 'yellow'), end="")
    for i in range(duration * 4):
        print(".", end="", flush=True)
        time.sleep(0.25)
    print(colored(" Done!", 'green'))

def display_result(is_safe, filename):
    """Display analysis result"""
    if is_safe:
        result_text = "SAFE"
        result_color = 'green'
        message = f"File '{filename}' appears to be safe"
    else:
        result_text = "THREAT DETECTED"
        result_color = 'red'
        message = f"WARNING: File '{filename}' may contain threats"
    
    display_banner(result_text, color=result_color)
    print(colored(message, result_color))

def main():
    """Main function to demonstrate display functionality"""
    display_welcome()
    time.sleep(1)
    display_random_message()
    time.sleep(1)
    display_loading(3)
    display_result(True, "example.txt")

if __name__ == "__main__":
    main()