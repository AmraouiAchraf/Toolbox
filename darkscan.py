#!/usr/bin/python
# -*- coding: utf-8 -*-
#===============================
#  By : 1ucif3r
#  Github.com/1ucif3r
#  instagram.com/0x1ucif3r
#  twitter.com/0x1ucif3r
#
#  www.dark4rmy.com
#================================
import sys
import os
import time
import signal
from time import sleep
from sys import argv
from platform import system

defaultportscan="50";

def darkmenu():
        print("\n \033[1;91m your output file is in your current directory \033[1;m")
        os.system("pwd")
        print(" \033[1;91m Your current directory \033[1;m")
        print("\n \033[1;91m1-) Back to Main Menu \n 2-) Exit \033[1;m")
        choicedonus = input("root""\033[1;91m@DarkScan:~$\033[1;m ")
        if choicedonus == "1":
            os.system("clear")
            darkscan()
        if choicedonus == "2":
            os.system("clear")
            print(" \033[1;91m@Good Bye !! Happy Hacking !!\033[1;m")
            sys.exit() 
        else:
            print(" Please enter one of the options in the menu. \n You are directed to the main menu.")
            time.sleep(2)
            darkscan()

def sigint_handler(signum, frame):
    os.system("clear")
    print ("CTRL+C detected!")
    print(" \033[1;91mGood Bye !! Happy Hacking !!\033[1;m")
    sys.exit() 
 
signal.signal(signal.SIGINT, sigint_handler)

os.system("clear")

def logo():
    print ("""\033[1;91m

               /\     ------  |    | |-----      /\     --------                
              /  \    |       |    | |    |     /  \    |                       
             /----\   |       |----| |----|    /----\   |----                       
            /      \  |       |    | |   \    /      \  |                   
           /        \ |-----  |    | |    \  /        \ |
                                                                          
             |_|  By : Achraf - Toolbox |_| 
\033[1;m """)


def menu():
    logo()
    print("""
        1-) Normal Scanning
        2-) Vulnerability Scanning
        00-) Contact
        0-) Exit
        """)
    

def darkscan():
    menu()
    

    choice = input("root""\033[1;91m@DarkScan:~$\033[1;m ")
    
    os.system('clear')
    if choice == "1":
        dscan()
    elif choice == "2":
        vul()
    elif choice == "u":
        update()
    elif choice == "00":
        credit()
    elif choice == "0":
        exit()
    elif choice == "":
        menu()
    else:
        print(" Please enter one of the options in the menu. \n You are directed to the main menu.")
        time.sleep(2)
        darkscan()
        
def dscan():
    os.system("clear")
    logo()
    print("""
        1-) Default Scan
        2-) Host Discovery
        3-) Nmap Script Engineering (default)
        00-) Back to Menu
        """)
   

    choicedscan = input("root""\033[1;91m@DScan:~$\033[1;m ")
    os.system('clear')
    if choicedscan == "1":
        os.system('clear')
        ds()
    if choicedscan == "2":
        os.system('clear')
        hd()
    if choicedscan == "3":
        os.system('clear')
        nse()
    elif choicedscan == "00":
        darkscan()

    
def vul():
    os.system("clear")
    logo()
    print("""
        1-) Default Vuln Scan (--script vuln)
        2-) FTP Vuln Scan
        3-) HTTP Vuln Scan
        4-) Stored XSS Vuln Scan
        5-) Dom Based XSS vuln Scan
        00-) Back to Menu
        """)
    

    choicevul = input("root""\033[1;91m@VulnerabilityScanning:~$\033[1;m ")
    os.system('clear')
    if choicevul == "1":
        os.system('clear')
        dvs()
    if choicevul == "2":
        os.system('clear')
        ftpvulscan()
    if choicevul == "3":
        os.system('clear')
        httpvulscan()
    if choicevul == "4":
        os.system('clear')
        storedxssscan()
    if choicevul == "5":
        os.system('clear')
        domxssscan()
    elif choicevul == "00":
        darkscan()
    

    
def ds():
        print(" Starting Default Scan...")
        time.sleep(1)
        os.system("clear")
        logo()
        print("     Enter your IP address (0.0.0.0) or example.com")
        print("")
        birhedef = input(" Enter Your Target: ")
        if not birhedef:
            print("Pls Enter Target")
            print("\033[1;91mYou are grounded! You go to the main menu...\033[1;m")
            time.sleep(2)
            os.system("clear")
            darkscan()
        else:
            topport1=input("Top Port? Example: 10 or 50, Default 50:  ")
            if not topport1:
                os.system("nmap -vv --top-ports="+defaultportscan+" "+birhedef+" -oN "+birhedef)
            else:
                os.system("nmap -vv --top-ports="+topport1+" "+birhedef+" -oN "+birhedef)
            
        darkmenu()

def hd():
        print(" Starting Host Discovery...")
        time.sleep(1)
        os.system("clear")
        logo()
        print("     Enter your IP address (0.0.0.0) or example.com")
        print("")
        ikihedef = input(" Enter Your Target: ")
        if not ikihedef:
            print("Pls Enter Target")
            print("\033[1;91mYou are grounded! You go to the main menu...\033[1;m")
            time.sleep(2)
            os.system("clear")
            darkscan()
        else:
            topport2=input("Top Port? Example: 10 or 50, Default 50:  ")
            if not topport2:
                os.system("nmap -vv -Pn --top-ports="+defaultportscan+" "+ikihedef+" -oN HostD-"+ikihedef+"-output")
            else:
                os.system("nmap -vv -Pn --top-ports="+topport2+" "+ikihedef+" -oN HostD-"+ikihedef+"-output")
            
        darkmenu()
    
def synscan():
        print(" Starting Port(SYN) Scan...")
        time.sleep(1)
        os.system("clear")
        logo()
        print("     Enter your IP address (0.0.0.0) or example.com")
        print("")
        uchedef = input(" Enter Your Target: ")
        if not uchedef:
            print("Pls Enter Target")
            print("\033[1;91mYou are grounded! You go to the main menu...\033[1;m")
            time.sleep(2)
            os.system("clear")
            darkscan()
        else:
            topport3=input("Top Port? Example: 10 or 50, Default 50:  ")
            if not topport3:
                os.system("nmap -vv -sS --top-ports="+defaultportscan+" "+uchedef+" -oN "+uchedef+"-output")
            else:
                os.system("nmap -vv -sS --top-ports="+topport3+" "+uchedef+" -oN "+uchedef+"-output")

        darkmenu()
    

    

            
        darkmenu()


def nullscan():
        print(" Null scan (-sN)")
        time.sleep(1)
        os.system("clear")
        logo()
        print("     Enter your IP address (0.0.0.0) or example.com")
        print("")
        altihedef = input(" Enter Your Target: ")
        if not altihedef:
            print("Pls Enter Target")
            print("\033[1;91mYou are grounded! You go to the main menu...\033[1;m")
            time.sleep(2)
            os.system("clear")
            darkscan()
        else:
            topport6=input("Top Port? Example: 10 or 50, Default 50:  ")
            if not topport6:
                os.system("nmap -vv -sN --top-ports="+defaultportscan+" "+altihedef+" -oN NullScan-"+altihedef+"-output")
            else:
                os.system("nmap -vv -sN --top-ports="+topport6+" "+altihedef+" -oN NullScan-"+altihedef+"-output")

        darkmenu()


    
def finscan():
        print(" FIN scan (-sF)")
        time.sleep(1)
        os.system("clear")
        logo()
        print("     Enter your IP address (0.0.0.0) or example.com")
        print("")
        yedihedef = input(" Enter Your Target: ")
        if not yedihedef:
            print("Pls Enter Target")
            print("\033[1;91mYou are grounded! You go to the main menu...\033[1;m")
            time.sleep(2)
            os.system("clear")
            darkscan()
        else:
            topport7=input("Top Port? Example: 10 or 50, Default 50:  ")
            if not topport7:
                os.system("nmap -vv -sF --top-ports="+defaultportscan+" "+yedihedef+" -oN FinScan-"+yedihedef+"-output")
            else:
                os.system("nmap -vv -sF --top-ports="+topport7+" "+yedihedef+" -oN FinScan-"+yedihedef+"-output")

        darkmenu()


        
        darkmenu()


def nse():
        print(" Starting Nmap Script Engineering...")
        time.sleep(1)
        os.system("clear")
        logo()
        print("     Enter your IP address (0.0.0.0) or example.com")
        print("")
        dokuzhedef = input(" Enter Your Target: ")
        if not dokuzhedef:
            print("Pls Enter Target")
            print("\033[1;91mYou are grounded! You go to the main menu...\033[1;m")
            time.sleep(2)
            os.system("clear")
            darkscan()
        else:
            topport9= input("Top Port? Example: 10 or 50, Default 50:  ")
            if not topport9:
                os.system("nmap -vv --script=default --top-ports="+defaultportscan+" " +dokuzhedef+" -oN ScScan-"+dokuzhedef+"-output")
            else:
                os.system("nmap -vv --script=default --top-ports="+topport9+" " +dokuzhedef+" -oN ScScan-"+dokuzhedef+"-output")
            
        darkmenu()


#Vulnerability Scan 'needs some tweaking'

def dvs():
        print("Default Vuln Scan ")
        time.sleep(1)
        os.system("clear")
        logo()
        print("     Enter your IP address (0.0.0.0) or example.com")
        print("")
        onuchedef = input(" Enter Your Target: ")
        if not onuchedef:
            print("Pls Enter Target")
            print("\033[1;91mYou are grounded! You go to the main menu...\033[1;m")
            time.sleep(2)
            os.system("clear")
            darkscan()
        else:
            topport13=input("\033[92mTop Port? Example 10 or 50, Default 50:\033[0m;  ")
            if not topport13:
                os.system("nmap -vv -sV -ff -Pn --top-ports="+defaultportscan+" --script vuln " +onuchedef+" -oN "+"VulnScanDef-"+onuchedef+"-output" )
            else:
                os.system("nmap -vv -sV -ff -Pn --top-ports="+topport13+" --script vuln " +onuchedef+" -oN "+"VulnScanDef-"+onuchedef+"-output" )
        
        darkmenu()


def ftpvulscan():
        print("FTP Vuln Scan ")
        time.sleep(1)
        os.system("clear")
        logo()
        print("     Enter your IP address (0.0.0.0) or example.com")
        print("")
        ondorthedef = input(" Enter Your Target: ")
        if not ondorthedef:
            print("Pls Enter Target")
            print("\033[1;91mYou are grounded! You go to the main menu...\033[1;m")
            time.sleep(2)
            os.system("clear")
            darkscan()
        else:
            topport14=input("\033[92mTop Port? Example 10 or 50, Default 50:\033[0m;  ")
            if not topport14:
                os.system("nmap -vv -sV -ff -Pn --top-ports="+defaultportscan+" --script ftp* " +ondorthedef+" -oN "+"FTPvuln-"+ondorthedef+"-output" )
            else:
                os.system("nmap -vv -sV -ff -Pn --top-ports="+topport14+" --script ftp* " +ondorthedef+" -oN "+"FTPvuln-"+ondorthedef+"-output" )
        
        darkmenu()


        
        darkmenu()


def httpvulscan():
        print("HTTP Vuln Scan ")
        time.sleep(1)
        os.system("clear")
        logo()
        print("     Enter your IP address (0.0.0.0) or example.com")
        print("")
        onaltihedef = input(" Enter Your Target: ")
        if not onaltihedef:
            print("Pls Enter Target")
            print("\033[1;91mYou are grounded! You go to the main menu...\033[1;m")
            time.sleep(2)
            os.system("clear")
            darkscan()
        else:
            topport16=input("\033[92mTop Port? Example 10 or 50, Default 50:\033[0m;  ")
            if not topport16:
                os.system("nmap -vv -sV -ff -Pn --top-ports="+defaultportscan+" --script smb* " +onaltihedef+" -oN "+"HTTPvuln-"+onaltihedef+"-output" )
            else:
                os.system("nmap -vv -sV -ff -Pn --top-ports="+topport16+" --script smb* " +onaltihedef+" -oN "+"HTTPvuln-"+onaltihedef+"-output" )
        
        darkmenu()   


        
        darkmenu() 

def storedxssscan():
        print("Stored XSS Vuln Scan ")
        time.sleep(1)
        os.system("clear")
        logo()
        print("     Enter your IP address (0.0.0.0) or example.com")
        print("")
        onsekizhedef = input(" Enter Your Target: ")
        if not onsekizhedef:
            print("Pls Enter Target")
            print("\033[1;91mYou are grounded! You go to the main menu...\033[1;m")
            time.sleep(2)
            os.system("clear")
            darkscan()
        else:
            topport18=input("\033[92mTop Port? Example 10 or 50, Default 50:\033[0m;  ")
            if not topport18:
                os.system("nmap -vv -sV -ff -Pn --top-ports="+defaultportscan+" --script=http-stored-xss.nse " +onsekizhedef+" -oN "+"StoredXSSvuln-"+onsekizhedef+"-output" )
            else:
                os.system("nmap -vv -sV -ff -Pn --top-ports="+topport18+" --script=http-stored-xss.nse " +onsekizhedef+" -oN "+"StoredXSSvuln-"+onsekizhedef+"-output" )
        
        darkmenu() 


def domxssscan():
        print("DOM Based XSS Vuln Scan ")
        time.sleep(1)
        os.system("clear")
        logo()
        print("     Enter your IP address (0.0.0.0) or example.com")
        print("")
        ondokuzhedef = input(" Enter Your Target: ")
        if not ondokuzhedef:
            print("Pls Enter Target")
            print("\033[1;91mYou are grounded! You go to the main menu...\033[1;m")
            time.sleep(2)
            os.system("clear")
            darkscan()
        else:
            topport19=input("\033[92mTop Port? Example 10 or 50, Default 50:\033[0m;  ")
            if not topport19:
                os.system("nmap -vv -sV -ff -Pn --top-ports="+defaultportscan+" --script=http-dombased-xss.nse " +ondokuzhedef+" -oN "+"DomBasedXSSvuln-"+ondokuzhedef+"-output" )
            else:
                os.system("nmap -vv -sV -ff -Pn --top-ports="+topport19+" --script=http-dombased-xss.nse " +ondokuzhedef+" -oN "+"DomBasedXSSvuln-"+ondokuzhedef+"-output" )
        
        darkmenu() 


def credit():
        print ("""\033[1;91m


               /\     ------  |    | |-----      /\     --------                
              /  \    |       |    | |    |     /  \    |                       
             /----\   |       |----| |----|    /----\   |----                       
            /      \  |       |    | |   \    /      \  |                   
           /        \ |-----  |    | |    \  /        \ |                      
                ===================================== 
          NOTE : For Back To Menu Press 1 OR For Exit Press 2
       ==========================================================                                                                   
\033[1;m """)
        
        print("""                 [!] Mail: \033[1;91mamraoui.achraf.sio@gmail.com\033[1;m\n
                 [!] Github: \033[1;91mhttps://github.com/AmraouiAchraf/Toolbox\033[1;m\n """)
        choicedonus = input("root""\033[1;91m@Credit:~$\033[1;m ")
        if choicedonus == "1":
            os.system("clear")
            darkscan()
        if choicedonus == "2":
            os.system("clear")
            print(" \033[1;91mGood Bye !! Happy Hacking !!\033[1;m")
            sys.exit() 
        else:
            print(" Please enter one of the options in the menu. \n You are directed to the main menu.")
            time.sleep(2)
            darkscan()

def exit():
        print(" \033[1;91mGood Bye !! Happy Hacking !!\033[1;m")
        sys.exit()




def rootcontrol():
    if os.geteuid()==0:
        darkscan()
    else:
        print ("Please run it with root access.")
        sys.exit()

rootcontrol()
