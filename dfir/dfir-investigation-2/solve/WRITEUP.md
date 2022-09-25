DFIR Investigation 2
=====================

When a user opens a document, a LNK file is created in the user's AppData directory. This is for the purpose of populating Windows 'recently accessed' lists in explorer.exe.

Knowing this behavior, we can correlate the creation time of the LNK with the first time that user opened a file by that name.

The LNK file for passwd.txt is located at:

C:\Users\Challenger\AppData\Roaming\Microsoft\Windows\Recent\passwd.lnk
The NTFS creation timestamp of passwd.lnk would answer the question, however to parse additional information about this file, we can extract it using FTK Imager and use LECmd (https://f001.backblazeb2.com/file/EricZimmermanTools/LECmd.zip) to process the LNK file.

.\LECmd.exe -f .\passwd.lnk
The "Source created" refers to the creation time of the LNK file, which corresponds to the time Challenger first opened passwd.txt.
The "Target created" is the NTFS creation timestamp of passwd.txt, which corresponds to when the file was created.

passwd.txt was not included in the forensic triage image. 
Participants are required to understand that very small files can be stored as resident data in the Master File Table (MFT).

Usually, the MFT record for a specific file will contain metadata relating to that file including file name, path, NTFS timestamp and location of the file on the drive. However, for very small files (~<700 bytes), the NTFS 'non-resident' record attribute is set to zero and the contents of the file are stored in the $DATA attribute of the $MFT record instead of in a separate disk location. More infromation can be read at https://www.sans.org/blog/resident-data-residue-in-ntfs-mft-entries/

Using this knowledge, participants can perform the following steps to identify the contents of passwd.txt:
1) Extract C:\$MFT from triage-skeleton-image.ad1 using FTK Imager
2) Open the MFT using a MFT parser which displays resident data, such as MFTExplorer (https://f001.backblazeb2.com/file/EricZimmermanTools/MFTExplorer.zip)
3) View the resident data of C:\Users\Challenger\Desktop\passwd.txt

Flag: `DUCTF{08:25:27_R3sident!al}`
