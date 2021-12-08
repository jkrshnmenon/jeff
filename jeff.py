from __future__ import print_function, division, absolute_import
import os
import re
import abc
import sys
import shlex
import fcntl
import struct
import string
import termios
import binascii
import traceback
import subprocess

### Configuration ###
RIGHT_ARROW = "->"
HORIZONTAL_LINE = "-"
# I WISH LLDB SUPPORTS COLORED PROMPT! FK!
LLNX_PROMPT_ON = "llnx(on)> "
LLNX_PROMPT_OFF = "llnx(off)> "

### Globals ###
__commands__                           = []
__config__                             = {}
DEFAULT_PAGE_ALIGN_SHIFT               = 12
DEFAULT_PAGE_SIZE                      = 1 << DEFAULT_PAGE_ALIGN_SHIFT
LLNX_MAX_STRING_LENGTH                 = 50

try:
    import lldb
except ImportError:
    print("[-] llnx cannot run as standalone")
    sys.exit(0)

try:
    from subprocess import DEVNULL # py3k
except ImportError:
    import os
    DEVNULL = open(os.devnull, 'wb')

def set_llnx_setting(name, value, _type=None, _desc=None):
    """Set global llnx settings.
    Raise ValueError if `name` doesn't exist and `type` and `desc`
    are not provided."""
    global __config__

    if name not in __config__:
        # create new setting
        if _type is None or _desc is None:
            raise ValueError("Setting '{}' is undefined, need to provide type and description".format(name))
        __config__[name] = [_type(value), _type, _desc]
        return

    # set existing setting
    func = __config__[name][1]
    __config__[name][0] = func(value)
    return

def get_llnx_setting(name):
    """Read global llnx settings.
    Return None if not found. A valid config setting can never return None,
    but False, 0 or ""."""
    global __config__
    setting = __config__.get(name, None)
    if not setting:
        return None
    return setting[0]

def get_process():
    """
    get current process
    """
    return lldb.debugger.GetSelectedTarget().process

def get_thread():
    """
    get current thread
    """
    return get_process().GetSelectedThread()

def get_frame():
    """
    get current frame
    """
    return get_thread().GetSelectedFrame()

def get_filepath():
    """
    get current file path
    """
    return get_process().target.executable.fullpath

def is_alive():
    """
    whether the target process is still alive
    """
    proc = get_process()
    if proc.GetProcessID() <= 0:
        return False
    if proc.GetExitStatus() >= 0:
        return False
    return True

def get_pid():
    """
    get the pid of the target process
    """
    return get_process().GetProcessID()

def llnx_prompt():
    """
    hook to change lldb's prompt
    """
    if is_alive(): return LLNX_PROMPT_ON
    return LLNX_PROMPT_OFF

def catch_error(func):
    """Decorator for catching error and show traceback for better debugging"""
    def new_func(*args, **kwargs):
        try:
            func(*args, **kwargs)
        except Exception:
            traceback.print_exc()
    return new_func

def register_command(cls):
    """Decorator for registering new LLNX command to LLDB."""
    __commands__.append(cls)
    return cls

def only_if_alive(func):
    """only run the function if the process is alive"""
    def new_func(*args, **kwargs):
        if not is_alive():
            err("Process is not running")
            return
        func(*args, **kwargs)
    return new_func

def add_all_commands():
    """
    add all registered commands to lldb
    """
    for cls in __commands__:
        cmd = 'command script add -f %s.%s.invoke -h "%s" %s' % (__name__, cls.__name__, cls._help_, cls._cmdline_)
        lldb.debugger.HandleCommand(cmd)

def hook_llnx_prompt():
    """
    hook llnx prompt
    """
    cmd = 'target stop-hook add -o llnx-prompt'
    lldb.debugger.HandleCommand(cmd)
    lldb.debugger.SetPrompt(llnx_prompt())

def is_hex(pattern):
    """Return whether provided string is a hexadecimal value."""
    if not pattern.startswith("0x") and not pattern.startswith("0X"):
        return False
    return len(pattern)%2==0 and all(c in string.hexdigits for c in pattern[2:])

def get_terminal_size():
    """Return the current terminal size."""
    try:
        cmd = struct.unpack("hh", fcntl.ioctl(1, termios.TIOCGWINSZ, "1234"))
        tty_rows, tty_columns = int(cmd[0]), int(cmd[1])
        return tty_rows, tty_columns

    except OSError:
        return 600, 100

def get_memory_alignment(in_bits=False):
    """Try to determine the size of a pointer on this system.
    First, try to parse it out of the ELF header.
    Next, use the size of `size_t`.
    Finally, try the size of $pc.
    If `in_bits` is set to True, the result is returned in bits, otherwise in
    bytes."""
    #TODO: OMG, what is this fking implementation! XD.
    return 8

def titlify(text, color=None, msg_color=None):
    """Print a centered title."""
    cols = get_terminal_size()[1]
    nb = (cols - len(text) - 2)//2
    if color is None:
        color = __config__.get("theme.default_title_line")[0]
    if msg_color is None:
        msg_color = __config__.get("theme.default_title_message")[0]

    msg = []
    msg.append(Color.colorify("{} ".format(HORIZONTAL_LINE * nb), color))
    msg.append(Color.colorify(text, msg_color))
    msg.append(Color.colorify(" {}".format(HORIZONTAL_LINE * nb), color))
    return "".join(msg)

def align_address(address):
    """Align the provided address to the process's native length."""
    if get_memory_alignment() == 4:
        return address & 0xFFFFFFFF

    return address & 0xFFFFFFFFFFFFFFFF

def parse_address(address):
    """Parse an address and return it as an Integer."""
    print([address])
    print(is_hex(address))
    if is_hex(address):
        return int(address, 16)
    # TODO: parse lldb variable
    raise ValueError("Currently, only number is accepted as a valid address")

def format_address(addr):
    """Format the address according to its size."""
    memalign_size = get_memory_alignment()
    addr = align_address(addr)

    if memalign_size == 4:
        return "0x{:08x}".format(addr)
    elif addr < 0x10:
        return hex(addr)

    return "0x{:016x}".format(addr)

def read_register(reg):
    """
    Read the content of register reg
    """
    frame = get_frame()
    return int(frame.register[reg].value, 16)

def read_memory(addr, length=0x10):
    """Return a `length` long byte array with the copy of the process memory at `addr`."""
    proc = get_process()
    return proc.ReadMemory(addr, length, lldb.SBError())

def read_cstring_from_memory(address, max_length=LLNX_MAX_STRING_LENGTH, encoding=None):
    """Return a C-string read from memory."""
    length = min(address|(DEFAULT_PAGE_SIZE-1), max_length+1)
    res = read_memory(address, length)

    res = res.split(b"\x00", 1)[0]
    ustr = res.replace(b"\n",b"\\n").replace(b"\r",b"\\r").replace(b"\t",b"\\t")
    if max_length and len(res) > max_length:
        return "{}[...]".format(ustr[:max_length])

    return ustr

def read_ascii_string(address):
    """Read an ASCII string from memory"""
    cstr = read_cstring_from_memory(address)
    if isinstance(cstr, bytes) and cstr and all([chr(x) in string.printable for x in cstr]):
        return cstr
    return None


def is_ascii_string(address):
    """Helper function to determine if the buffer pointed by `address` is an ASCII string (in GDB)"""
    try:
        return read_ascii_string(address) is not None
    except Exception as e:
        print(str(e))
        return False
    
def disassemble_addr(addr):
    """
    Disassemble one line at address addr
    """
    ci = lldb.debugger.GetCommandInterpreter()
    res = lldb.SBCommandReturnObject()
    out = ci.HandleCommand(f'disassemble -s {hex(addr)} -c 1', res)
    color = get_llnx_setting("theme.dereference_code")
    if out:
        func, line = res.GetOutput().splitlines()
        fname = func.split('`')[1].replace(':', '')
        disasm = line.split('<')[1]
        return " -> " + Color.colorify(f"<{fname}{disasm}", color)


def dereference_string(addr):
    """
    Dereference string at address addr
    """
    content = read_ascii_string(addr)
    if content is None:
        return ""
    return Color.colorify(content.decode('utf-8'), get_llnx_setting("theme.dereference_string"))


class Color:
    """Used to colorify terminal output."""
    colors = {
        "normal"         : "\033[0m",
        "gray"           : "\033[1;38;5;240m",
        "red"            : "\033[31m",
        "green"          : "\033[32m",
        "yellow"         : "\033[33m",
        "blue"           : "\033[34m",
        "pink"           : "\033[35m",
        "cyan"           : "\033[36m",
        "bold"           : "\033[1m",
        "underline"      : "\033[4m",
        "underline_off"  : "\033[24m",
        "highlight"      : "\033[3m",
        "highlight_off"  : "\033[23m",
        "blink"          : "\033[5m",
        "blink_off"      : "\033[25m",
    }

    @staticmethod
    def redify(msg):       return Color.colorify(msg, "red")
    @staticmethod
    def greenify(msg):     return Color.colorify(msg, "green")
    @staticmethod
    def blueify(msg):      return Color.colorify(msg, "blue")
    @staticmethod
    def yellowify(msg):    return Color.colorify(msg, "yellow")
    @staticmethod
    def grayify(msg):      return Color.colorify(msg, "gray")
    @staticmethod
    def pinkify(msg):      return Color.colorify(msg, "pink")
    @staticmethod
    def cyanify(msg):      return Color.colorify(msg, "cyan")
    @staticmethod
    def boldify(msg):      return Color.colorify(msg, "bold")
    @staticmethod
    def underlinify(msg):  return Color.colorify(msg, "underline")
    @staticmethod
    def highlightify(msg): return Color.colorify(msg, "highlight")
    @staticmethod
    def blinkify(msg):     return Color.colorify(msg, "blink")

    @staticmethod
    def colorify(text, attrs):
        """Color text according to the given attributes."""
        colors = Color.colors
        msg = [colors[attr] for attr in attrs.split() if attr in colors]
        msg.append(str(text))
        if colors["highlight"] in msg :   msg.append(colors["highlight_off"])
        if colors["underline"] in msg :   msg.append(colors["underline_off"])
        if colors["blink"] in msg :       msg.append(colors["blink_off"])
        msg.append(colors["normal"])
        return "".join(msg)

class Permission:
    """LLNX representation of UNIX permission."""
    NONE      = 0
    READ      = 1
    WRITE     = 2
    EXECUTE   = 4
    ALL       = READ | WRITE | EXECUTE

    def __init__(self, **kwargs):
        self.value = kwargs.get("value", 0)
        return

    def __or__(self, value):
        return self.value | value

    def __and__(self, value):
        return self.value & value

    def __xor__(self, value):
        return self.value ^ value

    def __eq__(self, value):
        return self.value == value

    def __ne__(self, value):
        return self.value != value

    def __str__(self):
        perm_str = ""
        perm_str += "r" if self & Permission.READ else "-"
        perm_str += "w" if self & Permission.WRITE else "-"
        perm_str += "x" if self & Permission.EXECUTE else "-"
        return perm_str

    @staticmethod
    def from_info_sections(*args):
        perm = Permission()
        for arg in args:
            if "READONLY" in arg:
                perm.value += Permission.READ
            if "DATA" in arg:
                perm.value += Permission.WRITE
            if "CODE" in arg:
                perm.value += Permission.EXECUTE
        return perm

    @staticmethod
    def from_process_maps(perm_str):
        perm = Permission()
        if perm_str[0] == "r":
            perm.value += Permission.READ
        if perm_str[1] == "w":
            perm.value += Permission.WRITE
        if perm_str[2] == "x":
            perm.value += Permission.EXECUTE
        return perm

class Section:
    """LLNX representation of process memory sections."""

    def __init__(self, **kwargs):
        self.page_start = kwargs.get("page_start")
        self.page_end = kwargs.get("page_end")
        self.permission = kwargs.get("permission")
        self.offset = kwargs.get("offset")
        self.path = kwargs.get("path")
        return
    

    def hex_align(self, val):
        return "0x{:016x}".format(val)

    def __str__(self):
        fmt = f"{self.hex_align(self.page_start)}-{self.hex_align(self.page_end)} {self.hex_align(self.offset)} {self.permission} {self.path}"
        if self.is_readable() and self.is_writable() and self.is_executable():
            return Color.underlinify(Color.colorify(fmt, get_llnx_setting("theme.address_code")))

        if self.is_readable() and self.is_executable():
            color = get_llnx_setting("theme.address_code")
        elif '[stack]' in self.path:
            color = get_llnx_setting("theme.address_stack")
        elif '[heap]' in self.path:
            color = get_llnx_setting("theme.address_heap")
        else:
            color = "normal"
        return Color.colorify(fmt, color)

    def is_readable(self):
        return self.permission.value and self.permission.value&Permission.READ

    def is_writable(self):
        return self.permission.value and self.permission.value&Permission.WRITE

    def is_executable(self):
        return self.permission.value and self.permission.value&Permission.EXECUTE

    @property
    def size(self):
        if self.page_end is None or self.page_start is None:
            return -1
        return self.page_end - self.page_start

class Address:
    """LLNX representation of memory addresses."""
    def __init__(self, *args, **kwargs):
        self.value = kwargs.get("value", 0)
        self.section = kwargs.get("section", None)
        self.info = kwargs.get("info", None)
        self.valid = kwargs.get("valid", True)
        return

    def __str__(self):
        # TODO: colored address does not work actually
        value = format_address(self.value)
        code_color = get_llnx_setting("theme.address_code")
        stack_color = get_llnx_setting("theme.address_stack")
        heap_color = get_llnx_setting("theme.address_heap")
        if self.is_in_text_segment() or self.is_in_executable_segment():
            return Color.colorify(value, code_color)
        if self.is_in_heap_segment():
            return Color.colorify(value, heap_color)
        if self.is_in_stack_segment():
            return Color.colorify(value, stack_color)
        return value

    def is_in_text_segment(self):
        return (hasattr(self.info, "name") and ".text" in self.info.name) or \
            (hasattr(self.section, "path") and get_filepath() == self.section.path and self.section.is_executable())

    def is_in_stack_segment(self):
        return hasattr(self.section, "path") and "[stack]" == self.section.path

    def is_in_heap_segment(self):
        return hasattr(self.section, "path") and "[heap]" == self.section.path
    
    def is_in_executable_segment(self):
        return hasattr(self.section, "permission") and self.section.is_executable()
    
    def is_in_readable_segment(self):
        return hasattr(self.section, "permission") and self.section.is_readable()

    def dereference(self):
        addr = align_address(int(self.value))
        derefed = dereference(addr)
        return None if derefed is None else int(derefed)

def err(msg):   return print("{} {}".format(Color.colorify("[!]", "bold red"), msg))
def warn(msg):  return print("{} {}".format(Color.colorify("[*]", "bold yellow"), msg))
def ok(msg):    return print("{} {}".format(Color.colorify("[+]", "bold green"), msg))
def info(msg):  return print("{} {}".format(Color.colorify("[+]", "bold blue"), msg))

def process_lookup_address(address):
    """Look up for an address in memory.
    Return an Address object if found, None otherwise."""
    if not is_alive():
        err("Process is not running")
        return None

    for sect in get_process_maps():
        if sect.page_start <= address < sect.page_end:
            return sect

    return None

def lookup_address(address):
    """Try to find the address in the process address space.
    Return an Address object, with validity flag set based on success."""
    sect = process_lookup_address(address)
    if sect is None:
        # i.e. there is no info on this address
        return Address(value=address, valid=False)
    return Address(value=address, section=sect, info=info)

def get_process_maps():
    """Parse output of `/usr/bin/vmmap`."""

    sections = []
    records = []

    pid = get_pid()
    while is_alive():
        try:
            output = subprocess.check_output(["/usr/bin/vmmap", str(pid)], stderr=DEVNULL).decode()
            break
        except FileNotFoundError:
            output = open(f"/proc/{pid}/maps", "r").read()
            break

    # grep mapping record
    pattern = re.compile('[rwx-]{3}p')
    for line in output.splitlines():
        if pattern.search(line) is None:
            continue

        # preprocess a mapping record
        try:
            match = re.match('([0-9a-f]{6,16})-([0-9a-f]{6,16})\s+.*([rwx-]{3}p)\s+([0-9a-f]+)\s+([0-9:]+)\s+([0-9]+)\s+(.*)', line)
            start_addr = int(match.group(1), 16)
            end_addr = int(match.group(2), 16)
            offset = int(match.group(4), 16)
            perm = Permission.from_process_maps(match.group(3))
            pathname = match.group(7)

            section = Section(
                              page_start=start_addr,
                              page_end=end_addr,
                              offset=offset,
                              permission=perm,
                              path=pathname)
            sections.append(section)

        except Exception as e:
            print(e)
            print(line)
            import IPython;IPython.embed()

    return sorted(sections, key=lambda s: s.page_start)

class LLNXCommand(object):
    @abc.abstractproperty
    def _cmdline_(self): pass

    @abc.abstractproperty
    def _syntax_(self): pass

    @abc.abstractproperty
    def _example_(self): return ""

    @abc.abstractmethod
    def do_invoke(self, argv): pass

    def err(self, msg):
        return print("{} {}".format(Color.colorify("[!]", "bold red"), msg))

    def warn(self, msg):
        return print("{} {}".format(Color.colorify("[*]", "bold yellow"), msg))

    def ok(self, msg):
        return print("{} {}".format(Color.colorify("[+]", "bold green"), msg))

    def info(self, msg):
        return print("{} {}".format(Color.colorify("[+]", "bold blue"), msg))

    def usage(self):
        self.err("Syntax\n{}".format(self._syntax_))
        return

    @classmethod
    @catch_error
    def invoke(cls, debugger, command, context, result, int_dict):
        # parse command and invoke the command
        cls().do_invoke(shlex.split(command))
        # TODO: figure out how to deal with result status elegantly
        result.SetStatus(lldb.eReturnStatusSuccessFinishNoResult)
        return

@register_command
class LLNXPromptCommand(LLNXCommand):
    _cmdline_ = 'llnx-prompt'
    _syntax_ = "debug"
    _example_ = "debug"
    _help_ = "This command is never designed to be called by user. It is used to hook lldb's prompt"


    def print_separator(self, m):
        rows, cols = get_terminal_size()
        fmt = "{:{padd}<{width}} ".format("", width=max(cols-len(m)-6, 0), padd=HORIZONTAL_LINE)
        tail = " {:{padd}<4}".format("", padd=HORIZONTAL_LINE)
        line_color = get_llnx_setting("theme.context_title_line")
        msg_color = get_llnx_setting("theme.context_title_message")
        print(Color.colorify(fmt, line_color) + Color.colorify(m, msg_color) + Color.colorify(tail, line_color))
    
    def pprint_content(self, content):
        addr = lookup_address(content)
        # return str(addr)

        if addr.is_in_executable_segment():
            return disassemble_addr(addr.value)
        elif addr.is_in_stack_segment() or addr.is_in_readable_segment():
            if is_ascii_string(addr.value):
                return ' -> ' + dereference_string(addr.value)
            else:
                content = read_memory(addr.value, 8)
                unpacked = struct.unpack("<Q", content)[0]
                return ' -> ' + str(lookup_address(unpacked)) + self.pprint_content(unpacked)
        
        return ""

    def print_stack(self):
        self.print_separator("stack")
        rsp = read_register('rsp')
        for x in range(8):
            addr = rsp+x*8
            content = read_memory(addr, 8)
            unpacked = struct.unpack("<Q", content)[0]
            print(
                str(lookup_address(addr)) + 
                "|+0x{:04x}: ".format(x*8) + 
                str(lookup_address(unpacked)) + self.pprint_content(unpacked)
                )
    
    def print_regs(self):
        self.print_separator("registers")
        register_color = get_llnx_setting("theme.register_name")
        regs = [
                "rax", "rbx", "rcx", "rdx", "rsp", "rbp", "rsi", "rdi", "rip",
                "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15" 
        ]
        for r in regs:
            content = read_register(r)
            print(
                Color.colorify("${:<6}".format(r), register_color) + 
                ": " + 
                str(lookup_address(content)) + self.pprint_content(content)
            )
    
    def show_legend(self):
        str_color = get_llnx_setting("theme.dereference_string")
        code_addr_color = get_llnx_setting("theme.address_code")
        stack_addr_color = get_llnx_setting("theme.address_stack")
        heap_addr_color = get_llnx_setting("theme.address_heap")
        register_color = get_llnx_setting("theme.register_name")

        print(
            "[ Legend: {} | {} | {} | {} | {} ]".format(
                                                        Color.colorify("Register", register_color),
                                                        Color.colorify("Code", code_addr_color),
                                                        Color.colorify("Heap", heap_addr_color),
                                                        Color.colorify("Stack", stack_addr_color),
                                                        Color.colorify("String", str_color)
        ))
        return

    def do_invoke(self, argv):
        os.system("clear -x")
        self.show_legend()
        self.print_regs()
        self.print_stack()
        self.print_separator("code:x86:64")
        return

@register_command
class DebugCommand(LLNXCommand):
    _cmdline_ = "debug"
    _syntax_ = "debug"
    _example_ = "debug"
    _help_ = "launch ipython shell for debugging"

    def do_invoke(self, argv):
        import IPython;IPython.embed()
        return

@register_command
class VMMAPCommand(LLNXCommand):
    _cmdline_ = "vmmap"
    _syntax_ = "vmmap [keyword]"
    _example_ = "vmmap"
    _help_ = "show virtual memory mmaping of current process"

    @only_if_alive
    def do_invoke(self, argv):
        keyword = argv[0].lower() if len(argv) > 0 else None
        sections = get_process_maps()
        headers = ["Start", "End", "Offset", "Perm", "Path"]
        print(Color.blueify("{:<{w}s}{:<{w}s}{:<{w}s}{:<4s} {:s}".format(*headers, w=19)))
        for sect in sections:
            if not keyword or keyword in sect.path.lower():
                print(str(sect))

@register_command
class SearchPatternCommand(LLNXCommand):
    """SearchPatternCommand: search a pattern in memory."""
    #TODO: If given an hex value (starting with 0x)
    #the command will also try to look for upwards cross-references to this address.

    _cmdline_ = "search-pattern"
    _syntax_  = "{:s} PATTERN [small|big] [section]".format(_cmdline_)
    _example_ = "\n{0:s} AAAAAAAA\n{0:s} 0x555555554000 little stack\n{0:s}AAAA 0x600000-0x601000".format(_cmdline_)
    _help_ = "search a pattern(string/hex number) in memory"

    def search_pattern_by_address(self, pattern, start_address, end_address):
        """Search a pattern within a range defined by arguments."""
        step = 0x400 * 0x1000
        locations = []

        for chunk_addr in range(start_address, end_address, step):
            if chunk_addr + step > end_address:
                chunk_size = end_address - chunk_addr
            else:
                chunk_size = step

            mem = read_memory(chunk_addr, chunk_size)

            for match in re.finditer(pattern, mem):
                start = chunk_addr + match.start()
                if is_ascii_string(start):
                    ustr = read_ascii_string(start)
                    end = start + len(ustr)
                else :
                    ustr = pattern.decode() + "[...]"
                    end = start + len(pattern)
                locations.append((start, end, ustr))

            del mem

        return locations

    def print_section(self, section):
        title = "In "
        if section.path:
            title += "'{}'".format(Color.blueify(section.path) )

        title += "({:#x}-{:#x})".format(section.page_start, section.page_end)
        title += ", permission={}".format(section.permission)
        ok(title)
        return

    def print_loc(self, loc):
        print("""  {:#x} - {:#x} {}  "{}" """.format(loc[0], loc[1], RIGHT_ARROW, Color.pinkify(loc[2]),))
        return

    def search_pattern(self, pattern, section_name):
        """Search a pattern within the whole userland memory."""
        for section in get_process_maps():
            if not section.permission & Permission.READ: continue
            if section.path == "dyld shared cache combined __LINKEDIT": continue
            if not section_name in section.path: continue

            start = section.page_start
            end   = section.page_end - 1
            old_section = None

            for loc in self.search_pattern_by_address(pattern, start, end):
                addr_loc_start = lookup_address(loc[0])
                if addr_loc_start and addr_loc_start.section:
                    if old_section != addr_loc_start.section:
                        self.print_section(addr_loc_start.section)
                        old_section = addr_loc_start.section

                self.print_loc(loc)
        return

    @only_if_alive
    def do_invoke(self, argv):
        argc = len(argv)
        if argc < 1:
            self.usage()
            return

        pattern = argv[0]

        if is_hex(pattern):
            pattern = b"".join([b"\\x"+pattern[i:i+2].encode() for i in range(len(pattern) - 2, 0, -2)])
        else:
            pattern = pattern.encode()

        info("Searching '{:s}' in memory".format(Color.yellowify(pattern.decode())))
        self.search_pattern(pattern, "libsystem_c.dylib")
        return

@register_command
class XAddressInfoCommand(LLNXCommand):
    """Retrieve and display runtime information for the location(s) given as parameter."""

    _cmdline_ = "xinfo"
    _syntax_  = "{:s} LOCATION".format(_cmdline_)
    _example_ = "{:s} $pc".format(_cmdline_)
    _help_ = "Retrieve and display runtime information for the location(s) given as parameter."

    @only_if_alive
    def do_invoke (self, argv):
        if not argv:
            self.err ("At least one valid address must be specified")
            self.usage()
            return

        for sym in argv:
            try:
                addr = align_address(parse_address(sym))
                print(titlify("xinfo: {:#x}".format(addr)))
                self.infos(addr)

            except Exception as e:
                self.err("{:s}".format(str(e)))
        return

    def infos(self, address):
        addr = lookup_address(address)
        if not addr.valid:
            self.warn("Cannot reach {:#x} in memory space".format(address))
            return

        sect = addr.section
        info = addr.info

        if sect:
            print("Page: {:s} {:s} {:s} (size={:#x})".format(format_address(sect.page_start),
                                                                 RIGHT_ARROW,
                                                                 format_address(sect.page_end),
                                                                 sect.page_end-sect.page_start))
            print("Permissions: {}".format(sect.permission))
            print("Pathname: {:s}".format(sect.path))
            print("Offset (from page): {:#x}".format(addr.value-sect.page_start))

        return

if __name__ == '__main__':
    print('error: this script is designed to be used within the embedded script interpreter in LLDB')
elif getattr(lldb, 'debugger', None):
    add_all_commands()
    hook_llnx_prompt()
    try:
        set_llnx_setting("theme.address_stack", "pink", str, _desc="Color to use when a stack address is found")
        set_llnx_setting("theme.address_heap", "green", str, _desc="Color to use when a heap address is found")
        set_llnx_setting("theme.address_code", "red", str, _desc="Color to use when a code address is found")
        set_llnx_setting("theme.context_title_line", "gray", str, _desc="Color of the borders in context window")
        set_llnx_setting("theme.context_title_message", "cyan", str, _desc="Color of the title in context window")
        set_llnx_setting("theme.default_title_line", "gray", str, _desc="Default color of borders")
        set_llnx_setting("theme.default_title_message", "cyan", str, _desc="Default color of title")
        set_llnx_setting("theme.register_name", "blue", str, _desc="Color of the register name")
        set_llnx_setting("theme.dereference_code", "gray", str, _desc="Color of dereferenced code")
        set_llnx_setting("theme.dereference_string", "yellow", str, _desc="Color of dereferenced string")
    except Exception as e:
        print(e)
