Assignment 2 
==========
Comp 116 - Security
Professor: Ming Chow 

### What Works/What Doesn't

**alarm.rb**, run without flags, detects NULL scans, XMAS scans, and      Credit Card numbers in the clear during a  live packet stream, alerting the user to the incident when it does occur. 

**alarm.rb**, run with a -r flag and a text file, detects and alerts the user to HTTP errors, NMAP scans, and
Shellcode. 

**NOTE:** I used the gem apachelogregex to parse the web log, and thus included a Gemfile so that
all that needs to be done is to run bundle install. 

### Usage

`bundle install`

`sudo ruby alarm.rb     //analyze live packet stream`

`sudo ruby alarm.rb -v [WEB_LOG]  // analyze web log`  

### Collaboration

Piazza/Ming 

### Time Spent

10 hrs

### Questions

1. Are the heuristics used in this assignment to determine incidents "even that good"?

   No. While it is relatively easy to record HTTP errors, detect Nmap scans/shellcode, and identify NULL and
   XMAS scans, it is equally as easy for a potential attacker to circumvent these detection methods. Furthemore,
   these are by no means the only way for an incident to occur. Thus, while this is a good start, it only
   covers a fraction of potential attacks that a computer faces on a network. 
2. If you have spare time in the future, what would you add to the program or do differently with regards to detecting incidents? 

   - More nmap detection to the packet scanners, especially targeted at some of the "stealthier" 
   scanning techniques, including: TCP FIN scan, FTP bounce, TCP connect scanning, and fragmentation scanning.
   - An option for some quick self-analysis, printing out basic stats about the state of the
   current machine and network the machine is on. I would especially attempt to point out ports that are
   unnecessarily open and identify if the machine is insecurely using VNC.
   - Saving the live capture stream for further analysis using WireShark or similar tools
   - Finding username/passwords in the clear
   - Statistics analysis for the web log results -- calculating with IP addresses occurred the most frequently
   and providing recommendations for banning the most frequent. 



