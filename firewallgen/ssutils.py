import re
import collections
import logging
from .logutils import debugcall

FIELDS = ["State", "Recv-Q", "Send-Q", "Local Address:Port",
          "Peer Address: Port", "Extras"]

logger = logging.getLogger(__name__)


def get_version_flag(version=4):
    versions = {
        6: "-6",
        4: "-4"
    }
    if version not in versions:
        raise ValueError("Please use either IPv4 or IPv6")
    return versions[version]


def get_tcp_listening(cmdrunner, version=4):
    return cmdrunner.check_output(["ss", "-nlpt", get_version_flag(version)])


def get_udp_listening(cmdrunner, version=4):
    return cmdrunner.check_output(["ss", "-nlpu", get_version_flag(version)])


def _parse_line(line):
    return re.split("[ ][ ]+", line)


def _peek_char(line):
    if len(line) == 0:
        return None
    return line[0]


def _get_char(line):
    return line[0], line[1:]


Identifier = collections.namedtuple('Identifier', 'data')
Number = collections.namedtuple('Number', 'data')
String = collections.namedtuple('String', 'data')
Punctuation = collections.namedtuple('Punctuation', 'data')


def _read_number(stream):
    value = ""
    while _peek_char(stream).isdigit():
        char, stream = _get_char(stream)
        value += char
    return Number(value), stream


def _read_identifier(stream):
    value = ""
    while _peek_char(stream).isalpha():
        char, stream = _get_char(stream)
        value += char
    return Identifier(value), stream


def _read_puncutation(stream):
    punc, stream = _get_char(stream)
    return Punctuation(punc), stream


def _read_string(stream):
    _, stream = _get_char(stream)
    str = ""
    try:
        next_, stream = _get_char(stream)
        while next_ != '"':
            str += next_
            next_, stream = _get_char(stream)
    except IndexError:
        raise ValueError('Ran out of chars looking for end of string')
    return String(str), stream


def tokenize_extras(stream):
    next_ = _peek_char(stream)
    tokens = []
    while next_:
        if next_.isspace():
            _, stream = _get_char(stream)
        elif next_.isalpha():
            token, stream = _read_identifier(stream)
            tokens.append(token)
        elif next_.isdigit():
            token, stream = _read_number(stream)
            tokens.append(token)
        elif next_ in [":", "=", "(", ")", ","]:
            token, stream = _read_puncutation(stream)
            tokens.append(token)
        elif next_ == '"':
            token, stream = _read_string(stream)
            tokens.append(token)
        else:
            raise ValueError("unexpected char: {}".format(next_))
        next_ = _peek_char(stream)
    return tokens


class AstNode(object):
    def accept(self, visitor):
        name = type(self).__name__.lower()
        method = getattr(visitor, "visit_{}".format(name))
        return method(self)


class AstList(AstNode):
    def __init__(self, children):
        self.children = children

    def __repr__(self):
        children_repr = [str(x) for x in self.children]
        return str(children_repr)


class AstAssignment(AstNode):
    def __init__(self, lhs, rhs):
        self.lhs = lhs
        self.rhs = rhs

    def __repr__(self):
        return "{}={}".format(self.lhs, self.rhs)


class AstMapping(AstNode):
    def __init__(self, lhs, rhs):
        self.lhs = lhs
        self.rhs = rhs

    def __repr__(self):
        return "{}:{}".format(self.lhs, self.rhs)


class AstIdentifier(AstNode):
    def __init__(self, ident):
        self.ident = ident

    def __repr__(self):
        return str(self.ident)


class AstNumber(AstNode):
    def __init__(self, number):
        self.number = number

    def __repr__(self):
        return str(self.number)


class AstString(AstNode):
    def __init__(self, str):
        self.str = str

    def __repr__(self):
        return '"{}"'.format(str)


class TokenBuffer:
    pointer = 0

    def __init__(self, tokens):
        self.tokens = tokens

    def peek(self):
        return self.tokens[self.pointer]

    def get(self):
        result = self.peek()
        self.pointer += 1
        return result


class AstGen:

    def __init__(self, tokens):
        self.token_buffer = TokenBuffer(tokens)

    def parse_ident(self):
        token = self.token_buffer.get()
        if not isinstance(token, Identifier):
            raise ValueError("expecting identifier")
        return AstIdentifier(token)

    def parse_string(self):
        token = self.token_buffer.get()
        if not isinstance(token, String):
            raise ValueError("expecting string")
        return AstString(token)

    def parse_number(self):
        token = self.token_buffer.get()
        if not isinstance(token, Number):
            raise ValueError("expecting number")
        return AstNumber(token)

    def parse_stmt(self):
        ident = self.parse_ident()
        next_ = self.token_buffer.get()
        if next_.data in [":", "="]:
            rhs = self.parse_expr()
            if next_ == "=":
                return AstAssignment(ident, rhs)
            else:
                return AstMapping(ident, rhs)
        else:
            raise ValueError("unexpected token: {}".format(next_))

    def parse_list(self):
        open_bracket = self.token_buffer.get()

        if open_bracket.data != "(":
            raise ValueError("expecting opening parenthesis")

        token = self.token_buffer.peek()
        children = []

        while not (isinstance(token, Punctuation) and token.data == ")"):
            if isinstance(token, String):
                # this is the name property of the dict
                name = self.parse_string()
                children.append(name)
            elif token.data == "(":
                child = self.parse_list()
                children.append(child)
            else:
                child = self.parse_stmt()
                children.append(child)
            token = self.token_buffer.peek()
            if token.data != "," and token.data != ")":
                raise ValueError("expecting: , or ), got: {}".format(token))
            elif token.data == ")":
                break
            elif token.data == ",":
                # don't process comma
                self.token_buffer.get()
            token = self.token_buffer.peek()

        # pop off final bracket
        if token.data != ")":
            raise ValueError("expecting list end")
        self.token_buffer.get()
        return AstList(children)

    def parse_expr(self):
        next_ = self.token_buffer.peek()
        if next_.data == "(":
            return self.parse_list()
        elif isinstance(next_, Identifier):
            return self.parse_ident()
        elif isinstance(next_, String):
            return self.parse_string()
        elif isinstance(next_, Number):
            return self.parse_number()
        else:
            raise ValueError("unexpected token: {}".format(next_))

    def get_ast(self):
        # assume only one statement
        return self.parse_stmt()


class Reformatter:
    def __init__(self):
        self.output = ""

    @debugcall
    def visit_astidentifier(self, ident):
        self.output += ident.ident.data

    @debugcall
    def visit_aststring(self, string):
        self.output += string.str.data

    @debugcall
    def visit_astnumber(self, number):
        self.output += number.number.data

    @debugcall
    def visit_astlist(self, list):
        if len(list.children) == 0:
            self.output += "[]"
        children = list.children
        isdict = False
        if isinstance(children[0], AstString):
            self.output += "{"
            isdict = True
            name = children[0].str.data
            self.output += '"name": "{}", '.format(name)
            children = children[1:]
        else:
            self.output += "["
        for i, child in enumerate(children):
            child.accept(self)
            if i < len(children) - 1:
                self.output += ","
        if isdict:
            self.output += "}"
        else:
            self.output += "]"

    @debugcall
    def visit_astassignment(self, assign):
        self.output += '"'
        assign.lhs.accept(self)
        self.output += '"'
        self.output += ": "
        assign.rhs.accept(self)

    @debugcall
    def visit_astmapping(self, mapping):
        self.output += '"'
        mapping.lhs.accept(self)
        self.output += '"'
        self.output += ": "
        mapping.rhs.accept(self)

    def get_output(self):
        return self.output


def parse_extras(extras):
    tokens = tokenize_extras(extras)
    parser = AstGen(tokens)
    ast = parser.get_ast()
    visitor = Reformatter()
    ast.accept(visitor)
    return eval("{" + visitor.get_output() + "}")


def parse_ss_output(output):
    # Ignore header for now
    if isinstance(output, str):
        output = iter(output.splitlines())
    _ = next(output)
    items = []
    for line in output:
        item = {}
        columns = _parse_line(line)
        for i, value in enumerate(columns):
            field = FIELDS[i]
            if field == "Extras":
                if value:
                    logger.info("extras: {}".format(value))
                    item[field] = parse_extras(value)
            else:
                item[field] = value
        items.append(item)
    return items
