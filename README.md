
Lenc
===========

LEnc is a Ruby gem that maintains encrypted repositories of files, enabling secure, encrypted
backups to free cloud services such as Dropbox, Google Drive, and Microsoft SkyDrive.

Written by Jeff Sember, March 2013.

[Source code documentation can be found here.](http://rubydoc.info/gems/lenc/frames)


Directory structure
--------
The program manipulates three distinct directories:

* A \<source\> directory, which holds all the
files to be encrypted.  The only file that the program modifies within this
directory tree is a hidden configuration file ".lenc" (on Windows, this file
is named "__lenc_repo__.txt").

* An \<encrypted\> directory, where the program stores the encrypted
versions of all the files found in the <source> directory.  This directory
is usually mapped to a cloud service (e.g., Dropbox), or perhaps to a thumb drive.
		
		NOTE:  THE <encrypted> DIRECTORY IS MANAGED BY THE PROGRAM!  
		ANY FILES WRITTEN TO THIS DIRECTORY BY THE USER MAY BE DELETED.

* A \<recover\> directory.  The program can recover a set of encrypted files here.
For safety, the this directory must not lie within an existing repository.


Running the program
----

The program can be asked to perform one of the following tasks:

__Setting up a repository.__  Select a directory you wish to be the \<source\> 
directory, and make it the current directory.  Type:
    
		lencrypt -i KEY ENCDIR
    
with KEY a set of characters (8 to 56 letters) to be used as the encryption key,
and ENCDIR the name of the \<encrypted\> directory (it must not already exist, and
it cannot lie within the current directory's tree).
 

__Updating a repository.__ From within a \<source\> directory tree, type:

		lencrypt
    
You will be prompted for the encryption key, and then the program will examine 
which files within the \<source\> directory have been changed (since the repository 
was created or last updated), and re-encrypt these into the \<encrypted\> directory.


__Recovering encrypted files.__  Type:

		lencrypt -r KEY ENCDIR RECDIR
    
with KEY the key associated with a repository whose encrypted files are stored in ENCDIR.
The recovered files will be stored in RECDIR.


Additional options can be found by typing:

		lencrypt -h
    
    
Ignore files
----------------
If desired, you can avoid storing selected files in the encryption repository.  
Within the \<source\> directory (or any of its subdirectories), place a text 
file '.lencignore' with a list of file or directory names (or patterns) to be 
ignored.  Example:

    # This is a comment
    #
    log
    *.mp3
    _SKIP_*
   
This causes the program to ignore any file or directory named 'log', as well as
any ending with ".mp3" or starting with "_SKIP_".

Some files are automatically ignored, e.g. ".DS_Store". 

The format of ignore files is similar to that of .gitignore files.  Details:
 
* Each line should contain a single pattern representing files or directories to be ignored.
* A line will be ignored (treated as a comment) if it is blank, or if it starts with '#'.
* The path separator should be '/' (Mac, Unix) or '\' (Windows).
* If a pattern starts with '#', you can precede it with '\' to avoid it being ignored.
* Precede a pattern with '!' to specifically include files/directories, overriding any previous
 		matching pattern in a parent directory.
* If a pattern ends with the path separator, it will be removed, and the pattern will
 		match only directories, not files.
* The wildcard '*' matches for any sequence of zero or more characters.
* The wildcard '?' matches any single character.
* If the pattern contains any path separators, then the wildcards '*', '?' will not
 		match the path separator.
 
Miscellaneous Issues
-------
* At present, the program will ignore any files (or directories) that are symbolic links.
 
