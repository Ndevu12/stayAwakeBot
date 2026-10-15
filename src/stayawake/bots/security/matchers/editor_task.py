"""Read an editor task the way the editor reads it: the names of its settings, and the command lines it
runs on each platform."""
from __future__ import annotations

_PLATFORMS = (None, "osx", "linux", "windows")


def named(value) -> str | None:
    """Return a task setting's name in lower case, as the editor reads it. Takes the value. Returns the
    name, or None when the value is not a name."""
    return value.lower() if isinstance(value, str) else None


def command_text(value) -> str | None:
    """Return the text of a command or an argument, written as a string, a list of strings or a quoted
    value. Takes the value. Returns the text, or None when there is none."""
    if isinstance(value, dict):
        value = value.get("value")
    if isinstance(value, str):
        return value
    if isinstance(value, list) and all(isinstance(part, str) for part in value):
        return " ".join(value)
    return None


def _command(scope: dict) -> tuple[str | None, list[str] | None]:
    """Return the command and the arguments one part of a task file sets. Takes that part. Returns the
    command and the arguments, each None when the part does not set it."""
    args = scope.get("args")
    texts = [text for text in map(command_text, args) if text is not None] if isinstance(args, list) else None
    return command_text(scope.get("command")), texts


def _for_platform(scope: dict, platform: str | None, replaces_arguments: bool):
    """Return the command and the arguments one part of a task file sets on a platform, with the block for
    that platform laid over the rest. Takes the part, the platform (None for no block) and whether the
    block's arguments replace the others rather than follow them. Returns the command and the arguments."""
    command, args = _command(scope)
    block = scope.get(platform) if platform else None
    if isinstance(block, dict):
        block_command, block_args = _command(block)
        if block_command is not None:
            command = block_command
        if block_args is not None:
            args = block_args if args is None or replaces_arguments else args + block_args
    return command, args


def _suppresses_task_name(scope: dict) -> bool | None:
    """Tell whether one part of a task file keeps the task's name off the command line. Takes the part.
    Returns the answer, or None when the part does not say."""
    value = scope.get("suppressTaskName")
    return value if isinstance(value, bool) else None


def command_lines(task: dict, task_file: dict) -> list[str]:
    """Return each command line the editor runs for a task: on every platform, with the block for that
    platform laid over the task, and the command the file sets for every task filling in a task that has
    none. Takes the task and the task file it sits in. Returns the lines, each once."""
    current = task_file.get("version") != "0.1.0"
    lines: list[str] = []
    for platform in _PLATFORMS:
        command, args = _for_platform(task, platform, current)
        if command is None:
            command, file_args = _for_platform(task_file, platform, current)
            suppressed = _suppresses_task_name(task)
            if suppressed is None:
                suppressed = _suppresses_task_name(task_file)
            if suppressed is None:
                suppressed = current
            label = task.get("label")
            if not (current and isinstance(label, str)):
                label = task.get("taskName")
            named_task = [label] if not suppressed and isinstance(label, str) and label else []
            args = (file_args or []) + named_task + (args or [])
        if command is None:
            continue
        line = " ".join([command, *(args or [])])
        if line not in lines:
            lines.append(line)
    return lines
