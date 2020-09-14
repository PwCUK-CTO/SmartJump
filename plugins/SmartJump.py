'''
   Copyright 2020 PricewaterhouseCoopers LLP

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

       http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.
'''
#v1.0

import idc, idaapi
import SmartJump.lex as lex
import SmartJump.yacc as yacc

#utilities
arch_size = 32
if idaapi.idainfo_is_64bit():
    arch_size = 64

#support x86 and x64 so check which pointers we will be accessing
def get_pointer(address):
    if arch_size == 32:
        return idaapi.get_dword(address)
    else:
        return idaapi.get_qword(address)

tokens = ('HERE', 'HEXADDR', 'ADDR', 'PLUS', 'LBRACKET', 'RBRACKET', 'LPAREN', 'RPAREN', 'MINUS', 'TIMES', 'DIVIDE',
    'EAX', 'EBX', 'ECX', 'EDX', 'EIP', 'ESI', 'EDI', 'EBP', 'ESP',
    'RAX', 'RBX', 'RCX', 'RDX', 'RIP', 'RSI', 'RDI', 'RBP', 'RSP', 'R8', 'R9', 'R10', 'R11', 'R12', 'R13', 'R14', 'R15', 'NAME',
    )

t_PLUS      = r'\+'
t_MINUS     = r'-'
t_LBRACKET  = r'\['
t_RBRACKET  = r'\]'
t_TIMES     = r'\*'
t_DIVIDE    = r'/'
t_LPAREN    = r'\('
t_RPAREN    = r'\)'

def t_HERE(t):
    r'(?i)here(\(\))?'
    t.value = idc.here()
    return t

def t_RAX(t):
    r'(?i)rax'
    t.value = idaapi.get_reg_val("RAX")
    return t

def t_RBX(t):
    r'(?i)rbx'
    t.value = idaapi.get_reg_val("RBX")
    return t

def t_RCX(t):
    r'(?i)rcx'
    t.value = idaapi.get_reg_val("RCX")
    return t

def t_RDX(t):
    r'(?i)rdx'
    t.value = idaapi.get_reg_val("RDX")
    return t

def t_RIP(t):
    r'(?i)rip'
    t.value = idaapi.get_reg_val("RIP")
    return t

def t_RSI(t):
    r'(?i)rsi'
    t.value = idaapi.get_reg_val("RSI")
    return t

def t_RDI(t):
    r'(?i)rdi'
    t.value = idaapi.get_reg_val("RDI")
    return t

def t_RBP(t):
    r'(?i)rbp'
    t.value = idaapi.get_reg_val("RBP")
    return t

def t_RSP(t):
    r'(?i)rsp'
    t.value = idaapi.get_reg_val("RSP")
    return t

def t_R8(t):
    r'(?i)r8'
    t.value = idaapi.get_reg_val("R8")
    return t

def t_R9(t):
    r'(?i)r9'
    t.value = idaapi.get_reg_val("R9")
    return t

def t_R10(t):
    r'(?i)r10'
    t.value = idaapi.get_reg_val("R10")
    return t

def t_R11(t):
    r'(?i)r11'
    t.value = idaapi.get_reg_val("R11")
    return t

def t_R12(t):
    r'(?i)r12'
    t.value = idaapi.get_reg_val("R12")
    return t

def t_R13(t):
    r'(?i)r13'
    t.value = idaapi.get_reg_val("R13")
    return t

def t_R14(t):
    r'(?i)r14'
    t.value = idaapi.get_reg_val("R14")
    return t

def t_R15(t):
    r'(?i)r15'
    t.value = idaapi.get_reg_val("R15")
    return t

def t_EAX(t):
    r'(?i)eax'
    if arch_size == 32:
        t.value = idaapi.get_reg_val("EAX")
    else:
        t.value = (idaapi.get_reg_val("RAX")) & 0xffffffff
    return t

def t_EBX(t):
    r'(?i)ebx'
    if arch_size == 32:
        t.value = idaapi.get_reg_val("EBX")
    else:
        t.value = (idaapi.get_reg_val("RBX")) & 0xffffffff
    return t

def t_ECX(t):
    r'(?i)ecx'
    if arch_size == 32:
        t.value = idaapi.get_reg_val("ECX")
    else:
        t.value = (idaapi.get_reg_val("RCX")) & 0xffffffff
    return t

def t_EDX(t):
    r'(?i)edx'
    if arch_size == 32:
        t.value = idaapi.get_reg_val("EDX")
    else:
        t.value = (idaapi.get_reg_val("RDX")) & 0xffffffff
    return t

def t_EIP(t):
    r'(?i)eip'
    if arch_size == 32:
        t.value = idaapi.get_reg_val("EIP")
    else:
        t.value = (idaapi.get_reg_val("RIP")) & 0xffffffff
    return t

def t_ESI(t):
    r'(?i)esi'
    if arch_size == 32:
        t.value = idaapi.get_reg_val("ESI")
    else:
        t.value = (idaapi.get_reg_val("RSI")) & 0xffffffff
    return t

def t_EDI(t):
    r'(?i)edi'
    if arch_size == 32:
        t.value = idaapi.get_reg_val("EDI")
    else:
        t.value = (idaapi.get_reg_val("RDI")) & 0xffffffff
    return t

def t_EBP(t):
    r'(?i)ebp'
    if arch_size == 32:
        t.value = idaapi.get_reg_val("EBP")
    else:
        t.value = (idaapi.get_reg_val("RBP")) & 0xffffffff
    return t

def t_ESP(t):
    r'(?i)esp'
    if arch_size == 32:
        t.value = idaapi.get_reg_val("ESP")
    else:
        t.value = (idaapi.get_reg_val("RSP")) & 0xffffffff
    return t

def t_NAME(t):
    r'[a-zA-Z_\.][a-zA-Z0-9_\.]*'
    temp = idc.get_name_ea_simple(t.value)
    if temp == idaapi.BADADDR:
        t.value = int(t.value, 16)
    else:
        t.value = temp
    return t

def t_HEXADDR(t):
    r'(?i)0x[0-9a-f]+'
    t.value = int(t.value[2:], 16)
    return t

def t_ADDR(t):
    r'(?i)[0-9a-f]+'
    t.value = int(t.value, 16)
    return t

t_ignore = " \t"

def t_newline(t):
    r'\n+'
    t.lexer.lineno += t.value.count("\n")

def t_error(t):
    debug_out(f"Illegal character {t.value[0]!r}")
    t.lexer.skip(1)

glob_lex = lex.lex()

precedence = (
    ('left','PLUS','MINUS'),
    ('left','TIMES','DIVIDE'),
)

def p_expression_binop(p):
    '''expression : expression PLUS expression
                | expression MINUS expression
                | expression TIMES expression
                | expression DIVIDE expression'''
    if p[2] == '+'  : p[0] = p[1] + p[3]
    elif p[2] == '-': p[0] = p[1] - p[3]
    elif p[2] == '*': p[0] = p[1] * p[3]
    elif p[2] == '/': p[0] = p[1] / p[3]
    
def p_expression_group(p):
    'expression : LPAREN expression RPAREN'
    p[0] = p[2]

def p_expression_deref(p):
    'expression : LBRACKET expression RBRACKET'
    p[0] = get_pointer(p[2])

def p_expression_hexaddr(p):
    'expression : HEXADDR'
    p[0] = p[1]

def p_expression_addr(p):
    'expression : ADDR'
    p[0] = p[1]

def p_expression_reg(p):
    '''expression : RAX
                | RBX
                | RCX
                | RDX
                | RSI
                | RDI
                | RBP
                | RSP
                | RIP
                | R8
                | R9
                | R10
                | R11
                | R12
                | R13
                | R14
                | R15
                | EAX
                | EBX
                | ECX
                | EDX
                | ESI
                | EDI
                | EBP
                | ESP
                | EIP
                | HERE'''
    p[0] = p[1]

def p_expression_name(p):
    'expression : NAME'
    p[0] = p[1]

def p_error(p):
    print(f"Syntax error at {p.value!r}")

glob_parser = yacc.yacc()

def debug_out(str):
    print ("[SMARTJUMPER]: %s" % str)

class SmartJump_t(idaapi.plugin_t):
    flags = 0
    comment = "Smart IDA jumping"
    wanted_hotkey = 'g'
    help = "Runs by replacing Go command when pressing g"
    wanted_name = "SmartJumper"
    lexer = None
    parser = None
    
    def init(self):
        global glob_lex
        global glob_parser
        if idaapi.ph_get_id() != idaapi.PLFM_386:
            return idaapi.PLUGIN_SKIP
        debug_out("Loading Parsers")
        
        self.lexer = glob_lex
        self.parser = glob_parser
        debug_out("Loaded SmartJumper")
        return idaapi.PLUGIN_KEEP

    def run(self, arg=0):
        jump_str = idaapi.ask_str("", 0, "Jump expression...")
        if jump_str != None:
            try:
                open_deref = jump_str.count("[")
                close_deref = jump_str.count("]")
                if close_deref < open_deref:
                    jump_str += "]" * (open_deref-close_deref)
                if open_deref < close_deref:
                    debug_out("mismatched dereferences")
                else:
                    result = self.parser.parse(jump_str, lexer=self.lexer)
                    debug_out("resolved to %08x" % result)
                    idaapi.jumpto(result)
            except:
                debug_out("problem parsing")

    def term(self):
        return

def PLUGIN_ENTRY():
    return SmartJump_t()