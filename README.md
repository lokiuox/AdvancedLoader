# Advanced Loader

This project is an experimental advanced shellcode loader which include many features to lower EDR detection rates.    

At the moment, the implemented features are the following:
- Using [DInvoke](https://github.com/TheWover/DInvoke) (instead of PInvoke) to call Win32 API functions stealthly 
- Option to automatically detect and unhook NTDLL APIs hooked by EDRs before jumping to shellcode
- Can load shellcode from standard binary files or from specially crafted "smart shellcode files"
- Support of keyed and encrypted payloads using smart shellcodes

## Smart shellcode files
"Smart shellcodes" can be generated using the attached python script; they are basically text files made of a short header followed by the hex-encoded payload.    
    
The payload is just the (optionally) XOR-encrypted shellcode. When executed, the XOR encryption key is constructed from properties of the target environment, such as the current username, domain or hostname, and optionally a custom password which will be asked during execution.    
When generating the shellcode using the script, you can choose dynamically which bits of the target environment you want to use for the key, and in which order.    
    
The "smart" bit lies in the fact that the information on how to reconstruct the key is stored in the header of the file, so that you don't have to recompile the project any time you want to change the key, the loader will simply look at the header and know which pieces it needs and in which order.
