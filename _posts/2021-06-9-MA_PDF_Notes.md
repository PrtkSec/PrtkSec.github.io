---
title: "Notes for Analysing Malicious PDF Documents" 
author: Pratik Patel
date: 2021-06-9
categories: [Malware Analysis Notes]
tags: [PDF Analysis, pdfid, pdf-parser, peepdf, YARA]
---

# Purpose

The purpose of this post is to cover steps & tools for analysing malicious PDF documents. I will be using both the FlareVM and REMnux for analysis purposes. The steps taken will be covered in the following order below:

**1. Understand the PDF file structure**

**2. Identify point of interests during Analysis**

**3. Tools to find and extract data**  

I will be using the following malicious PDF file (badpdf.pdf) throughout this post. The file is available from hybrid-analysis (HA) with the following hash:

> **_MD5:_**  2264DD0EE26D8E3FBDF715DD0D807569

> **_SHA256:_**  ad6cedb0d1244c1d740bf5f681850a275c4592281cdebb491ce533edd9d6a77d

(WARNING! Download at your own risk!)

## 1. Understand the PDF file structure

PDF (Portable Document Format) is a file format used to present documents that include text, images, multimedia elements, web page links and more. it consists of objects contained in the body section of a PDF file; it also supports scripting capabilities in the form of Action Scripts (such as JavaScript).

There are 4 sections in a PDF file:
1. **Header** *(contains the version number of the pdf file)*
2. **Body** *(contains objects - obj values (1 0) denotes its name and its version number, obj & endobj refers to the beginning and end of an object, contains catalog and stream objects)*
3. **Cross Reference Table** *(allows the pdf parser to quickly access every object inside the Body, begins with the keyword xref)*
4. **Trailer** (contains overall info about the PDF, points to the start of Cross Reference Table)

the image below depicts the 4 sections as described above:
![alt text](/assets/img/pdf_notes/pdf_structure.png)

## 2. Identify point of interests during Analysis

## PDF Element Actions

- **/OpenAction /AA** - the function of this element is to carry out an action for e.g. execute a script
- **/JavaScript /JS** - link to the JavaScript that will run when the PDF is opened
- **/Names** - names of files that will likely be referred to by the PDF itself
- **/EmbeddedFile** - shows the other files embedded within the PDF file itself e.g., scripts
- **/URI /SubmitForm** - Links to other URLs on the internet e.g., possible link to a 2nd stage payload/additional tools for malware to run
- **/Launch** - Similar to OpenAction, can be used to run embedded scripts within the PDF file itself or run new additional files that have been downloaded by the PDF

## PDF Strings, Encoding & Decoding

PDF can encode strings in multiple ways to obfuscate data, the following example shows the string "Hello World" before and after hex encoding.

![alt text](/assets/img/pdf_notes/string_encode.png)

Some additional encoding examples:
![alt text](/assets/img/pdf_notes/encoding.png)

To decode the encoded data PDF uses Filters, which tell the PDF reader that the corresponding string is supposed to be decoded using the provided method, as shown below:
![alt text](/assets/img/pdf_notes/decode_1.png)

Example of multiple decode filters:

![alt text](/assets/img/pdf_notes/multiple_filters.png) 

This has two levels of obfuscation, first is hex encoding and second is compression. The PDF reader will uncompress the stream data first before decoding the hex value (NOTE: Multiple filters are decoded in reverse).

## PDF Obfuscation Methods
- **/ASCIIHexDecode** - hex encoding of characters
- **/LZWDecode** - LZW compression algorithm
- **/FlateDecode** - Zlib compression
- **/ASCII85Decode** - ASCII base-85 representation
- **/Crypt** - Various encryption algorithms

## 3. Tools to find and extract data

- **pdfid** - identifies PDF object types and filters (useful for triage of PDF documents), however it only indicates what is in the document not where
- **pdf-parser** - parses, searches and extracts data from PDF documents (use the pdfid tool first and then analyse the suspicious PDFs with pdf-parser)
- **peepdf** - is the combination of pdfid & pdf-parser, as it is able to find suspicious objects, decode data and has JavaScript analysis built-ins
- **YARA** - a tool that is used to examine suspected files/directories and match strings as defined in the YARA rules with the file.

### pdfid in FlareVM & REMnux
Commands:
> **_FlareVM:_**  `python pdfid.py "location of badpdf.pdf file"`

> **_REMnux:_**  `pdfid.py "location of badpdf.pdf file"`

![alt text](/assets/img/pdf_notes/pdfid.png)

### pdf-parser in REMnux (same output in FlareVM but looks cleaner on REMnux :) )
as stated before, pdf-parser will extract all the data from a PDF. In order to narrow down to "the items of interest" we need to use the built-in command options such as '--Search'.

Use pdfparser with --search to show the /OpenAction object
> **_REMnux:_** `pdf-parser.py --search openaction badpdf.pdf`

![alt text](/assets/img/pdf_notes/openaction.png)

Now let's search for the Javascript object with pdfparser
> **_REMnux:_** `pdf-parser.py --search javascript badpdf.pdf`

![alt text](/assets/img/pdf_notes/obj712.png)

locating object 10 and object 13 using the pdf parser

> **_REMnux:_** `pdf-parser.py --object 10  badpdf.pdf`

> **_REMnux:_** `pdf-parser.py --object 13  badpdf.pdf`

![alt text](/assets/img/pdf_notes/obj1013.png)

To tell pdf-parser to apply the filter, use the -f (filter) & -w (raw output) option:

> **_REMnux:_** `pdf-parser.py --object 13 -f -w badpdf.pdf`

![alt text](/assets/img/pdf_notes/rawoutput.png)

In order to format the code, we need to dump the output to a separate file and use a suitable JavaScript editor (Visual Studio Code).
the command below will output a separate file

> **_REMnux:_** `pdf-parser.py --object 13 -f -w -d obj13 badpdf.pdf`

![alt text](/assets/img/pdf_notes/dump13.png)

use Visual Studio Code to open the file and examine the content.

![alt text](/assets/img/pdf_notes/vsdump.png)

I will analyse the code later, but for now let’s use pdf-parser with YARA rules to scan if the content in object 13 is malicious.

![alt text](/assets/img/pdf_notes/yaraparser.png)

so according to the above image, pdf-parser with YARA was able to detect the piece of code in object 13 as malicious.


### pee-pdf in REMnux

> **_REMnux:_** `peepdf -i badpdf.pdf`

![alt text](/assets/img/pdf_notes/peepdf.png)

We can also use the above hash values and check on virustotal if the file is malicious (which it is as shown below). we can further analyse the objects, let's try object 13 as we know it contains the JavaScript code.

![alt text](/assets/img/pdf_notes/vtotal.png)

![alt text](/assets/img/pdf_notes/obj13un.png)

we can also dump the object 13 content + JavaScript code to a file with the following command:

> **_REMnux:_** `PPDF> object 13 > obj13.js`

That concludes the use of the peepdf tool.

# Summary
All of the tools used above proved to be quite useful for PDF document analysis. Peepdf definitely has the upper hand over pdfid and pdf-parser as they require a lot of manual analysis. All in all they are all quite useful when used in conjunction (pdfid + pdf-parser + YARA). 

# References

| Description                                                           	| Link                                                                                                                             	|
|-----------------------------------------------------------------------	|----------------------------------------------------------------------------------------------------------------------------------	|
| Hybrid Analysis badpdf.pdf file (WARNING! Download at your own risk!) 	| https://www.hybrid-analysis.com/sample/ad6cedb0d1244c1d740bf5f681850a275c4592281cdebb491ce533edd9d6a77d/5ba8ca967ca3e15fe24d1c93 	|
| Flare VM (for Malware Analysis)                                       	| https://github.com/fireeye/flare-vm                                                                                              	|
| REMnux VM (for Malware Analysis)                                      	| https://docs.remnux.org/install-distro/get-virtual-appliance                                                                     	|

