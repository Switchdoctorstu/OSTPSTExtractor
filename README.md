# OSTPSTExtractor
Python programme to iterate OST or PST files and extract emails complete with attachments

Recurses Folders within the PST or OST file.
Writes out Mail elements found into separate .eml files in a folder structure taken from the PST or OST file structure

For the inbox folder i found the emails as sub-items so i recursed those elements too.
Saves all attachments found as attachments in the new .eml file.

Only issue is that i couldn't work out how to get the attachemnet filenames from the PST file.
Normally it's in a ContentDisposition statement but i couldn't wrk out where to get these from so i just named them sequntially.
