Assignment 1 
==========
Comp 116 - Security
Professor: Ming Chow 

### set1.pcap
1. How many packets are there in this set?   
  **1503**

2. What protocol was used to transfer files from PC to server?

  **FTP** 
3. Briefly describe why the protocol used to transfer the files is insecure?

  **The files transferred from PC to server are not encrypted or protected, 
therefore it is possible to easily reconstruct their content.**

4. What is the secure alternative to the protocol used to transfer files?
  **SSL** 

5. What is the IP address of the server?

  **67.23.79.113**
6. What was the username and password used to access the server?
  **USER:** ihackpineapples 

  **PASS:** rockyou1
7. How many files were transferred from PC to server?
  **4** 
8. What are the names of the files transferred from PC to server?
  1. BjN-O1hcAAAZbiq.jpg 
  2. BvgT9p21QAEEoHu.jpg
  3. BvzjaN-IQAA3XG7.jpg
  4. smash.txt 

### set2.pcap 
10. How many packets are there in this set?

  **77882**
11. How many plaintext username-password pairs are there in this packet set?
  
  **2**
12. Briefly describe how you found the username-password pairs.

  **I used ettercap to read the pcap and then grep to find plaintext username/password pairs.**
13. For each of the plaintext username-password pair that you found, identify the protocol used, server IP, the corresponding domain name (e.g., google.com), and port number.

    1. username: 1, 
           password: "" 
	   protocol: HTTP
	   server IP: 75.127.96.187
 	   domain: http://defcon-wireless-village.com 
	   port number: 80
 2. username: chris@digitalinterlude.com, 
       password: Volrathw69 
	   protocol:POP
	   server IP: 75.126.75.131
 	   domain: mail.si-sv2321.com  
	   port number: 110

14. Of all the plaintext username-password pairs that you found, how many of them are legitimate? That is, the username-password was valid, access successfully granted?

  **The first was invalid and the second was valid.**

15. How did you verify the successful username-password pairs?
  **I went into wireshark and filtered by IP address. Then I followed the TCP stream to determine if the call was successful.** 

16. What advice would you give to the owners of the username-password pairs that you found so their account information would not be revealed "in-the-clear" in the future?

  Research your email service providers--find out what protocol they use to transfer emails, 
how they secure your data, and what security breaches have occurred in the past. Based on this
research, use only the email service providers who are known to be secure. And, if for whatever
reason you absolutely must use an insecure provider, especially one using POP, do not use the sameusername/password that you use anywhere else.  
