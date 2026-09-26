"""Мини-интерпретатор подмножества cmd.exe для проверки Launch.bat.

Зачем это нужно
---------------
Жалоба «Launch.bat открывается на долю секунды и вылетает» означает, что
интерпретатор не доходит до строки запуска программы. Проверить это на Linux
нечем, поэтому здесь реализовано подмножество семантики cmd.exe, достаточное
для наших шаблонов:

* метки, ``goto``, ``call :label``, ``goto :eof``;
* ``set "K=V"``, ``set "K="``, подстановка ``%VAR%`` и ``%VAR:~a,b%``;
* аргументы ``%1``/``%~1``/``%~f1``, ``shift``;
* ``if``/``if not`` с ``==``, ``/i``, ``exist``, ``defined``;
* многострочные блоки в скобках и ``else``;
* ``for %%I in (...) do ...`` по списку значений;
* ``mkdir``, ``del``, ``copy``, ``pushd``/``popd``, ``echo``, ``rem``, ``title``;
* ``exit /b N`` и ``endlocal & exit /b N``;
* запуск внешней программы (``"%TARGET%" args``) — фиксируется, не выполняется.

Неизвестная команда — это ошибка теста: так мы ловим опечатки в шаблоне.
Симулятор намеренно строгий: он не «прощает» то, что настоящий cmd.exe тоже
не простил бы.
"""
from __future__ import annotations

import ntpath
import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple


class BatError(Exception):
    """Ошибка разбора/исполнения — в тестах означает сломанный .bat."""


@dataclass
class FakeFS:
    """Регистронезависимая файловая система Windows в памяти."""

    files: Dict[str, str] = field(default_factory=dict)
    dirs: set = field(default_factory=set)

    @staticmethod
    def _norm(path: str) -> str:
        return ntpath.normpath(path).rstrip("\\").lower()

    def add_file(self, path: str, content: str = "") -> None:
        self.files[self._norm(path)] = content
        parent = ntpath.dirname(ntpath.normpath(path))
        while parent and parent not in ("\\", ""):
            self.dirs.add(self._norm(parent))
            new_parent = ntpath.dirname(parent)
            if new_parent == parent:
                break
            parent = new_parent

    def add_dir(self, path: str) -> None:
        self.dirs.add(self._norm(path))

    def exists(self, path: str) -> bool:
        path = path.strip('"')
        if not path:
            return False
        norm = self._norm(path)
        if norm in self.files or norm in self.dirs:
            return True
        # Поддержка шаблона ...\*.reg в проверках exist/for.
        if "*" in norm or "?" in norm:
            return bool(self.glob(path))
        return False

    def glob(self, pattern: str) -> List[str]:
        pattern = pattern.strip('"')
        norm = self._norm(pattern)
        regex = re.compile(
            "^" + re.escape(norm).replace(r"\*", "[^\\\\]*").replace(r"\?", "[^\\\\]") + "$")
        return sorted(p for p in list(self.files) + list(self.dirs) if regex.match(p))

    def remove(self, pattern: str) -> None:
        for path in self.glob(pattern):
            self.files.pop(path, None)

    def copy(self, src: str, dst: str) -> None:
        src_norm = self._norm(src)
        if src_norm in self.files:
            self.add_file(dst, self.files[src_norm])


@dataclass
class Launch:
    """Зафиксированный запуск внешней программы."""

    command: str
    args: str
    cwd: str


@dataclass
class Result:
    exit_code: Optional[int] = None
    output: List[str] = field(default_factory=list)
    launches: List[Launch] = field(default_factory=list)
    reg_commands: List[str] = field(default_factory=list)
    env: Dict[str, str] = field(default_factory=dict)
    paused: int = 0

    @property
    def text(self) -> str:
        return "\n".join(self.output)

    @property
    def launched(self) -> bool:
        return bool(self.launches)


_LABEL_RE = re.compile(r"^:([A-Za-z_][\w]*)\s*$")


class BatchInterpreter:
    """Исполняет подмножество .bat, достаточное для наших лончеров."""

    MAX_STEPS = 20000

    def __init__(self, text: str, script_path: str, fs: FakeFS,
                 argv: Optional[List[str]] = None,
                 env: Optional[Dict[str, str]] = None,
                 program_exit_code: int = 0) -> None:
        if not text.isascii():
            raise BatError("файл содержит не-ASCII байты: cmd.exe собьёт разбор")
        self.lines = text.replace("\r\n", "\n").split("\n")
        self.script_path = script_path
        self.fs = fs
        self.argv = list(argv or [])
        self.env: Dict[str, str] = {
            "TEMP": r"C:\Windows\Temp",
            "PATH": r"C:\Windows\system32",
            "RANDOM": "1234",
            **(env or {}),
        }
        self.program_exit_code = program_exit_code
        self.result = Result(env=self.env)
        self.cwd = ntpath.dirname(script_path)
        self.dir_stack: List[str] = []
        self.call_stack: List[int] = []
        self.call_argv_stack: List[List[str]] = []
        self.errorlevel = 0
        self.labels = self._index_labels()

    # -- подготовка -----------------------------------------------------------
    def _index_labels(self) -> Dict[str, int]:
        labels: Dict[str, int] = {}
        for index, line in enumerate(self.lines):
            match = _LABEL_RE.match(line.strip())
            if match:
                labels.setdefault(match.group(1).lower(), index)
        return labels

    # -- подстановка ----------------------------------------------------------
    def expand(self, text: str) -> str:
        # %~dp0 / %~f0 и аргументы %1..%9 с модификаторами.
        def arg_sub(match: "re.Match[str]") -> str:
            mods, index = match.group(1) or "", int(match.group(2))
            value = (self.script_path if index == 0
                     else (self.argv[index - 1] if index <= len(self.argv) else ""))
            if "~" in mods:
                value = value.strip('"')
            if "f" in mods and value:
                value = ntpath.normpath(ntpath.join(self.cwd, value))
            if "d" in mods and "p" in mods:
                value = ntpath.dirname(ntpath.normpath(value)) + "\\"
            elif "d" in mods:
                value = ntpath.splitdrive(value)[0]
            elif "p" in mods:
                value = ntpath.dirname(ntpath.splitdrive(value)[1]) + "\\"
            if "n" in mods:
                value = ntpath.splitext(ntpath.basename(value))[0]
            if "x" in mods:
                value = ntpath.splitext(value)[1]
            return value

        text = re.sub(r"%(~[fdpnx]*)?(\d)", arg_sub, text)

        # %VAR:~start,len% и %VAR%
        def var_sub(match: "re.Match[str]") -> str:
            name, slice_spec = match.group(1), match.group(2)
            value = self.env.get(name.upper(), self.env.get(name, ""))
            if slice_spec:
                parts = slice_spec.lstrip("~").split(",")
                start = int(parts[0]) if parts[0] else 0
                if len(parts) > 1 and parts[1]:
                    length = int(parts[1])
                    value = (value[start:start + length] if length >= 0
                             else value[start:length])
                else:
                    value = value[start:]
            return value

        text = re.sub(r"%([A-Za-z_][\w()]*)((?::~[^%]*)?)%",
                      lambda m: var_sub(
                          re.match(r"%([A-Za-z_][\w()]*)(?::(~[^%]*))?%", m.group(0))
                          or m),
                      text)
        return text.replace("%%", "%")

    # -- исполнение -----------------------------------------------------------
    def run(self) -> Result:
        index, steps = 0, 0
        while index < len(self.lines):
            steps += 1
            if steps > self.MAX_STEPS:
                raise BatError("бесконечный цикл: .bat не доходит до конца")
            line = self.lines[index].strip()
            index += 1
            if not line or line.startswith("::") or _LABEL_RE.match(line):
                continue
            block, index = self._read_block(line, index)
            jump = self._exec(block)
            if jump is None:
                continue
            kind, payload = jump
            if kind == "exit":
                self.result.exit_code = payload
                return self.result
            if kind == "goto":
                if payload == "eof":
                    if self.call_stack:
                        index = self.call_stack.pop()
                        if self.call_argv_stack:
                            self.argv = self.call_argv_stack.pop()
                        continue
                    self.result.exit_code = self.errorlevel
                    return self.result
                if payload not in self.labels:
                    raise BatError(f"переход на несуществующую метку :{payload}")
                index = self.labels[payload] + 1
            elif kind == "call":
                if payload not in self.labels:
                    raise BatError(f"call на несуществующую метку :{payload}")
                self.call_stack.append(index)
                index = self.labels[payload] + 1
        self.result.exit_code = self.errorlevel
        return self.result

    def _read_block(self, line: str, index: int) -> Tuple[str, int]:
        """Собирает многострочный блок ``( ... )`` в одну логическую команду."""
        depth = self._depth(line)
        while depth > 0 and index < len(self.lines):
            line += "\n" + self.lines[index]
            depth += self._depth(self.lines[index])
            index += 1
        return line, index

    @staticmethod
    def _depth(line: str) -> int:
        depth, in_quotes = 0, False
        for ch in line:
            if ch == '"':
                in_quotes = not in_quotes
            elif not in_quotes:
                if ch == "(":
                    depth += 1
                elif ch == ")":
                    depth -= 1
        return depth

    @staticmethod
    def _split_top(text: str, sep: str) -> List[str]:
        parts, current, depth, in_quotes = [], "", 0, False
        i = 0
        while i < len(text):
            ch = text[i]
            if ch == '"':
                in_quotes = not in_quotes
            elif not in_quotes:
                if ch == "(":
                    depth += 1
                elif ch == ")":
                    depth -= 1
                elif depth == 0 and text.startswith(sep, i):
                    # ``2>&1`` — это перенаправление, а не разделитель команд.
                    if not (sep == "&" and current.rstrip().endswith(">")):
                        parts.append(current)
                        current = ""
                        i += len(sep)
                        continue
            current += ch
            i += 1
        parts.append(current)
        return parts

    def _exec(self, command: str):
        for part in self._split_top(command, "&"):
            part = part.strip()
            if not part:
                continue
            jump = self._exec_single(part)
            if jump is not None:
                return jump
        return None

    def _exec_single(self, command: str):
        command = command.strip()
        # Срезаем хвостовые перенаправления (>nul, 2>nul, 2>&1 и их сочетания).
        command = re.sub(r"(?:\s*\d?>(?:&\d|[^\s\"]+))+\s*$", "", command).strip()
        low = command.lower()

        if low.startswith("@"):
            return self._exec_single(command[1:])
        if low.startswith("rem") or low in ("echo off", "@echo off"):
            return None
        if low.startswith("setlocal") or low.startswith("title"):
            return None
        if low == "endlocal":
            return None
        if low.startswith("if "):
            return self._exec_if(command[3:].strip())
        if low.startswith("for "):
            return self._exec_for(command[4:].strip())
        if low.startswith("goto"):
            return ("goto", command.split(None, 1)[1].strip().lstrip(":").lower())
        if low.startswith("call "):
            target = command[5:].strip()
            if target.startswith(":"):
                name, _, rest = target[1:].partition(" ")
                # cmd.exe раскрывает аргументы ДО передачи в подпрограмму,
                # и внутри неё %1 — это первый аргумент вызова, а не скрипта.
                self.call_argv_stack.append(self.argv)
                self.argv = ([self.expand(a).strip('"')
                              for a in self._tokens(rest)] if rest.strip()
                             else [])
                return ("call", name.lower())
            program, _, args = target.partition(" ")
            program = self.expand(program.strip('"'))
            if self.fs.exists(program):
                tokens = self._tokens(self.expand(args).strip())
                parsed_args = [t.strip('"') for t in tokens]
                child_text = self.fs.files.get(self.fs._norm(program), "")
                sub = BatchInterpreter(child_text, program, self.fs,
                                       argv=parsed_args,
                                       env=dict(self.env),
                                       program_exit_code=self.program_exit_code)
                sub_res = sub.run()
                self.result.launches.extend(sub_res.launches)
                self.result.reg_commands.extend(sub_res.reg_commands)
                self.result.output.extend(sub_res.output)
                self.errorlevel = sub_res.exit_code or 0
                self.env["ERRORLEVEL"] = str(self.errorlevel)
                return None
            return None
        if low.startswith("exit"):
            match = re.search(r"/b\s*(-?\d+|%\w+%)?", command, re.IGNORECASE)
            raw = (match.group(1) if match and match.group(1) else "0")
            return ("exit", int(self.expand(raw) or 0))
        if low.startswith("set "):
            self._exec_set(command[4:].strip())
            return None
        if low.startswith("echo"):
            rest = command[4:]
            self.result.output.append(
                "" if rest.strip() in (".", "") else self.expand(rest).strip())
            return None
        if low == "pause" or low.startswith("pause"):
            self.result.paused += 1
            return None
        if low.startswith("mkdir") or low.startswith("md "):
            self.fs.add_dir(self.expand(command.split(None, 1)[1]).strip('"'))
            return None
        if low.startswith("del "):
            for token in self._tokens(command[4:]):
                if not token.startswith("/"):
                    self.fs.remove(self.expand(token))
            return None
        if low.startswith("copy "):
            tokens = [t for t in self._tokens(command[5:])
                      if not t.startswith("/")]
            if len(tokens) >= 2:
                self.fs.copy(self.expand(tokens[0]), self.expand(tokens[1]))
            return None
        if low.startswith("pushd"):
            self.dir_stack.append(self.cwd)
            self.cwd = self.expand(command.split(None, 1)[1]).strip('"')
            return None
        if low == "popd":
            if self.dir_stack:
                self.cwd = self.dir_stack.pop()
            return None
        if low.startswith("reg "):
            self.result.reg_commands.append(self.expand(command))
            self.errorlevel = 0
            return None
        if low.startswith("powershell"):
            self.errorlevel = 0
            return None
        if low.startswith("shift"):
            self.argv = self.argv[1:]
            return None
        if command.startswith('"'):
            # Запуск внешней программы или другого .bat.
            program, _, args = command[1:].partition('"')
            program = self.expand(program)
            if program.lower().endswith(".bat") and self.fs.exists(program):
                tokens = self._tokens(self.expand(args).strip())
                parsed_args = [t.strip('"') for t in tokens]
                child_text = self.fs.files.get(self.fs._norm(program), "")
                sub = BatchInterpreter(child_text, program, self.fs,
                                       argv=parsed_args,
                                       env=dict(self.env),
                                       program_exit_code=self.program_exit_code)
                sub_res = sub.run()
                self.result.launches.extend(sub_res.launches)
                self.result.reg_commands.extend(sub_res.reg_commands)
                self.result.output.extend(sub_res.output)
                self.errorlevel = sub_res.exit_code or 0
                self.env["ERRORLEVEL"] = str(self.errorlevel)
                return None
            if not self.fs.exists(program):
                raise BatError(f"запуск несуществующего файла: {program}")
            self.result.launches.append(
                Launch(program, self.expand(args).strip(), self.cwd))
            self.errorlevel = self.program_exit_code
            self.env["ERRORLEVEL"] = str(self.program_exit_code)
            return None
        raise BatError(f"неизвестная команда: {command!r}")

    @staticmethod
    def _tokens(text: str) -> List[str]:
        return re.findall(r'"[^"]*"|\S+', text.strip())

    def _exec_set(self, rest: str) -> None:
        rest = rest.strip()
        if rest.lower().startswith("/p "):
            rest = rest[3:].strip()
            if rest.startswith('"') and rest.endswith('"'):
                rest = rest[1:-1]
            name, sep, prompt = rest.partition("=")
            if name:
                var_name = name.strip()
                mock_key = f"INPUT_{var_name.upper()}"
                if mock_key in self.env:
                    self.env[var_name.upper()] = self.env[mock_key]
                elif var_name.upper() not in self.env:
                    self.env[var_name.upper()] = "1"
            return
        if rest.startswith('"') and rest.endswith('"'):
            rest = rest[1:-1]
        name, sep, value = rest.partition("=")
        if not sep:
            return
        name = name.strip()
        value = self.expand(value)
        if value == "":
            self.env.pop(name.upper(), None)
            self.env.pop(name, None)
        else:
            self.env[name.upper()] = value

    def _exec_if(self, rest: str):
        negate = False
        while True:
            low = rest.lower()
            if low.startswith("not "):
                negate = not negate
                rest = rest[4:].strip()
            elif low.startswith("/i "):
                rest = rest[3:].strip()
            else:
                break

        low = rest.lower()
        if low.startswith("exist "):
            rest = rest[6:].strip()
            token, rest = self._take_token(rest)
            condition = self.fs.exists(self.expand(token))
        elif low.startswith("defined "):
            rest = rest[8:].strip()
            token, rest = self._take_token(rest)
            name = self.expand(token).strip('"')
            condition = name.upper() in self.env or name in self.env
        else:
            left, rest = self._take_token(rest)
            rest = rest.strip()
            operator = "=="
            if rest.startswith("=="):
                rest = rest[2:].strip()
            else:
                raise BatError(f"неподдерживаемое условие if: {rest!r}")
            right, rest = self._take_token(rest)
            condition = (self.expand(left).strip('"').lower()
                         == self.expand(right).strip('"').lower())

        if negate:
            condition = not condition

        body, else_body = self._split_if_bodies(rest.strip())
        chosen = body if condition else else_body
        if chosen is None:
            return None
        return self._exec_body(chosen)

    @staticmethod
    def _take_token(text: str) -> Tuple[str, str]:
        text = text.strip()
        if text.startswith('"'):
            end = text.index('"', 1)
            return text[: end + 1], text[end + 1:]
        match = re.match(r"\S+", text)
        if not match:
            return "", text
        return match.group(0), text[match.end():]

    def _split_if_bodies(self, rest: str) -> Tuple[str, Optional[str]]:
        rest = rest.strip()
        if not rest.startswith("("):
            # Однострочная форма; else на той же строке не используем.
            return rest, None
        depth, in_quotes = 0, False
        for i, ch in enumerate(rest):
            if ch == '"':
                in_quotes = not in_quotes
            elif not in_quotes:
                if ch == "(":
                    depth += 1
                elif ch == ")":
                    depth -= 1
                    if depth == 0:
                        body = rest[1:i]
                        tail = rest[i + 1:].strip()
                        if tail.lower().startswith("else"):
                            tail = tail[4:].strip()
                            if tail.startswith("("):
                                return body, tail[1:tail.rindex(")")]
                            return body, tail
                        return body, None
        raise BatError("незакрытая скобка в if")

    def _exec_body(self, body: str):
        lines = body.split("\n")
        index = 0
        while index < len(lines):
            raw = lines[index].strip()
            index += 1
            if not raw or raw.startswith("::") or _LABEL_RE.match(raw):
                continue
            block, index = self._read_block_from_list(lines, raw, index)
            jump = self._exec(block)
            if jump is not None:
                return jump
        return None

    def _read_block_from_list(self, lines: List[str], line: str, index: int) -> Tuple[str, int]:
        depth = self._depth(line)
        while depth > 0 and index < len(lines):
            line += "\n" + lines[index]
            depth += self._depth(lines[index])
            index += 1
        return line, index

    def _exec_for(self, rest: str):
        match = re.match(r"%%(\w)\s+in\s*\((.*?)\)\s*do\s+(.*)$", rest,
                         re.IGNORECASE | re.DOTALL)
        if not match:
            raise BatError(f"неподдерживаемый for: {rest!r}")
        var, items_raw, body = match.groups()
        items: List[str] = []
        for token in self._tokens(items_raw.replace("\n", " ")):
            value = self.expand(token).strip('"')
            items.extend(self.fs.glob(value) if ("*" in value or "?" in value)
                         else [value])
        for item in items:
            expanded = body
            for modifier, transform in (
                ("~f", lambda v: ntpath.normpath(ntpath.join(self.cwd, v))),
                ("~dp", lambda v: ntpath.dirname(ntpath.normpath(v)) + "\\"),
                ("~", lambda v: v.strip('"')),
                ("", lambda v: v),
            ):
                expanded = expanded.replace(f"%%{modifier}{var}", transform(item))
            jump = self._exec_body(expanded)
            if jump is not None:
                return jump
        return None


def run_batch(text: str, script_path: str, fs: FakeFS, **kwargs) -> Result:
    return BatchInterpreter(text, script_path, fs, **kwargs).run()
