import re
# Compile ONCE (important for speed)
METHOD_START_RE = re.compile(
    r"""
    ^\s*
    (?:@[\w\.]+(?:\([^)]*\))?\s*)*   # annotations
    (?:
        public|protected|private|
        static|final|abstract|
        synchronized|native|
        strictfp
    )*\s*
    (?:<[^>]+>\s*)?                  # generics
    (?:[\w\[\]<>?,\s]+\s+)?          # return type (absent for constructors)
    \w+\s*                           # method / constructor name
    \([^;]*\)                        # parameters
    (?:\s+throws\s+[\w\.,\s]+)?      # throws clause
    \s*\{                            # opening brace
    """,
    re.VERBOSE
)

CONTROL_KEYWORDS = ("if", "for", "while", "switch", "catch", "do", "else", "try", "synchronized")

def preprocess_java_code(java_code: str) -> str:
    """
    Apply regex filters to remove decompiler-generated artefacts.
    """
    # patterns = [
    #     r"(?s)/\*.*?JADX.*?\*/",       # Remove multi-line JADX comments
    #     r"//\s*JADX[^\n]*",             # Remove single-line JADX notes
    #     r"//\s*(synthetic|bridge)\b.*", # Remove synthetic/bridge comments
    #     r"//\s*(Code|Instructions):.*", # Remove placeholder markers
    #     r"/\*\s*compiled from:.*?\*/",  # Remove compiled from metadata
    #     r"/\*\s*renamed from:.*?\*/",
    #     r"/\*\s*loaded from:.*?\*/",
    #     r"//.*",
    # ]
    patterns = [
        # JADX block comments
        r"/\*\s*JADX.*?\*/",
        # JADX renamed/loaded metadata
        r"/\*\s*(?:renamed from|loaded from|compiled from):.*?\*/",
        # JADX single-line comments
        r"//\s*JADX[^\n]*",
        # synthetic/bridge comments
        r"//\s*(?:synthetic|bridge)\b[^\n]*",
        # JADX Code/Instructions markers
        r"//\s*(?:Code|Instructions):[^\n]*",
    ]
    
    cleaned_code = java_code
    for pattern in patterns:
        cleaned_code = re.sub(pattern, "", cleaned_code, flags=re.MULTILINE)
    
    # Remove empty lines and trailing whitespace
    cleaned_code = "\n".join(line.rstrip() for line in cleaned_code.splitlines() if line.strip())
    return cleaned_code 


def parse_java_blocks(java_code: str):
    """
    Fast Java block parser:
    - Extracts METHOD blocks
    - Everything else goes into REST
    - Regex + brace depth only
    """
    java_code = java_code.strip()
    if not java_code:
        return []

    lines = java_code.splitlines()
    blocks = []
    rest_buffer = []
    method_buffer = []
    in_method = False
    brace_depth = 0

    for line in lines:
        stripped = line.strip()
        # Count braces early (important)
        open_braces = line.count("{")
        close_braces = line.count("}")
        # Detect method start
        if not in_method:
            if (METHOD_START_RE.match(line) and not stripped.startswith(CONTROL_KEYWORDS)):
                # Flush REST
                if rest_buffer:
                    blocks.append({"type": "REST", "text": "\n".join(rest_buffer).strip()})
                    rest_buffer = []
                in_method = True
                method_buffer = [line]
                brace_depth = open_braces - close_braces
                continue
            else:
                rest_buffer.append(line)
                continue
        # Inside method
        method_buffer.append(line)
        brace_depth += open_braces - close_braces
        if brace_depth == 0:
            blocks.append({"type": "METHOD", "text": "\n".join(method_buffer).strip()})
            method_buffer = []
            in_method = False
    # Flush leftovers
    if method_buffer:
        blocks.append({"type": "METHOD", "text": "\n".join(method_buffer).strip()})
    if rest_buffer:
        blocks.append({"type": "REST", "text": "\n".join(rest_buffer).strip()})
    return blocks