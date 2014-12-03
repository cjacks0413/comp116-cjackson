Comp116 Assignment 5 - Forensics

---

**Group partners:**  
Cameron Jackson  
Eric Bailey

Due 12/04/14

---

**Part I - Image differences**  
*Two of the pictures are identical and the other is the odd one out. Reveal any
hidden information in the picture that is different from the others. Please
detail your steps!*

We determined that b.jpg differed from the rest, isolating b.jpg using diff. Then, we used steghide to confirm that hidden data was located within b.jpg. We cracked the passphrase (“disney”) using brute force, which gave us the executable runme, which, when ran with a command line argument (our name), it said we were doing a “heckuvajob up to this point”.  

---

**Part II - Disk analysis**  
*What is/are the disk format(s) of the disk on the suspect's computing device?*  
Two partitions on the disk file we were given: Win95 FAT32 (0x0c); Linux (0x83)

*Is there a phone carrier involved?*  
There was no evidence of mobile phone files on any partition of this disk image; the two partitions (installed as Kali Linux and a Windows partition) did not contain any large amounts of files pertaining to cellular devices. Thus, there does not appear to be a phone carrier involved in this investigation.

*What operating system, including version number, is being used? Please elaborate
how you determined this information.*  
Kali Linux 1.0.9
We discovered this information by simply viewing the file /etc/debian_version, which had the contents “Kali Linux 1.0.9”

*What applications are installed on the disk? Please elaborate how you determined
this information*  
Major Kali Linux applications, including (but not limited to):

* In /etc -- bluetooth, calendar, chatscripts, emacs, ImageMagick, john, mysql, selinux, wireshark
* In /usr/bin -- apt-get, bitmap, csum, grep, hexdump
* In /usr/share/applications & /usr/share/apps -- bluetooth, konsole

We found this information by perusing the standard Linux application directories in Autopsy.

*Is there a root password? If so, what is it?*  
Yes - the root password is “princess”. We found this by using John the Ripper’s wordlist on /etc/passwd and /etc/shadow after combining them via unshadow

*Are there any additional user accounts on the system? If so, what are their
passwords?*  
Via the same method of cracking passwords, we found the following passwords to the other user accounts:

* stefani - iloveyou
* judas - 00000000
* alejandro - pokerface

*List some of the incriminating evidence that you found. Please elaborate where
and how you uncovered the evidence.*  

* Video of Lady Gaga’s performance - vintage\_nyu\_performance.mp4 (on the user stefani).  
* Many pictures - found on the / directory of alejandro’s user account.
* sched.txt - contains a list of Lady Gaga’s performances.  

We found all this evidence via autopsy’s File Analysis Browser, and saved the files for viewing via the Export method.

*Did the suspect move or try to delete any files before his arrest? Please list
the name(s) of the file(s) and any indications of their contents that you can
find*  
a15.jpg, a16.jpg, a17.jpg were deleted: We know this because of the indications (red highlighting) on autopsy’s deleted file identification support.  
Also, a file called note.txt was deleted by the user stefani (indication: bash history includes: “vim note.txt; rm note.txt”).

*Did the suspect save pictures of the celebrity? If so, how many pictures of the
celebrity did you find? (including any deleted images)*  
There appear to be 17 images under the user account alejandro (a1-a17.jpg), 3 of which were deleted (a15-a17.jpg).

*Are there any encrypted files? If so, list the contents and a brief description
of how you obtained the contents.*  
There is an encrypted file; Namely, lockbox.txt. After downloading the file’s contents, we ran the command “file lockbox.txt,” through which we learned that the file is a Zip file. After trying to unzip it with a standard unzipping program, we saw that it was password protected. Then, we used a password list along with a simple shell script to brute force the password. However, we needed to add some password guesses related to the other information found on the disk to uncover the actual password (such as ‘alejandro’, ‘ladygaga’, ‘lady’, ‘gaga’, etc.). Luckily, we found that the actual password is ‘gaga’. Entering this password unencrypted the zip file and the contents were released - a 23.5MB video file called edge.mp4 which was a music video of Lady Gaga performing.

*Do the suspect want to go see this celebrity? If so, note the date(s) and
location(s) where the suspect want see to the celebrity.*  
Yes: as found in sched.txt, the suspected wanted to see the celebrity at:
12/31/2014: The Chelsea at the Cosmopolitan of Las Vegas Las Vegas, NV 9:00 p.m. PST
2/8/2015: Wiltern Theatre, Los Angeles, CA, 9:30 p.m. PST
5/30/2015: Hollywood Bowl, Hollywood, CA, 7:30 p.m. PDT


*Who is the celebrity that the suspect has been stalking?*  
Lady Gaga (Stefani Germanotta)



