IDA Pro plugin to enhance the JumpAsk 'g' command


# Installation

Copy the contents of the plugin folder into your IDA_DIR/plugin folder  
Edit `IDA_DIR\cfg\idagui.cfg` so that the line that has default text with:  
    `"JumpAsk"    = 'g'`  
Instead reads:  
    `"JumpAsk"    = 0`  
You can append the text:  
    `// 'g'`  
To the line to give a full entry of:  
    `"JumpAsk"    = 0 // 'g'`  
If you do not want to remember what the default value was.  

# Usage

SmartJump is designed to improve the `g` keyboard shortcut in IDA, especially when using IDA to debug binaries. It allows a user to do basic mathematical operations `-`, `+`, `/`, `*` on values and labels in the JumpAsk window.  
In addition, it allows a user to use the symbols `[` and `]` to dereference memory addresses and jump to the values contained at the address.  

The supported type of values that can be used in the jumpask window are:  
    `here` and `here()` - these resolve to the current result of `idc.here()`  
    `main` and `sub_123456` - you can still jump by names/labels in the binary  
    `12ab34` and `0x12ab34` - all numbers are interpreted as hexadecimal numbers and can either be preceded by `0x` or not. If a global name also matches a hexadecimal number pattern then the global name will take precedence  
    `eax`, `ebx`, ... , `rax`, ... - 32 and 64 bit registers for x86 and x64 are supported. Using `eax` on an x64 binary will mask the lower 32 bits and return that value  

All of these values can be used in combinations, a brief but inexhaustive list of examples is below:  
    `[eax]` - Grabs the current value in eax, goes to the memory location and attempts to read a 32 bit pointer if in IDA32 or a 64 bit pointer if in IDA64. If the resolution is a valid address then it jumps there  
    `[here] + rsp` - Grabs the value stored at the current address and adds it to the 64 bit stack pointer then jumps to the resulting stack location  
    `[[ebx]*4]+[edx]` - You are starting to get the picture, you can do any jumps that resolve to an address in IDA...  

You can use the symbols `(` and `)` to explicitly group operations together rather than relying on the precedences assigned for the operators  
E.g.  
    `0x1200 * ([ebx] + here)` - This will grab the contents of ebx, add the current address to it and then multiply it by 0x1200 and try to jump to the result  

You do not have to match `[` and `]` symbols:  
    `[[[eax` - This will automatically have enough `]` symbols appended to the end of the query to match the opening `[` symbols  
               The final result would be a triple dereference of eax - `[[[eax]]]`  
               The matching brace completion only supports the `[` symbol currently and will not match `(` symbols. All auto added braces are put at the end of the input expression  
