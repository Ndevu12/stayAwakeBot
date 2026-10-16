"""Read an editor task the way the editor reads it: the names of its settings, the command lines it runs on
each platform, and whether it keeps itself out of sight."""
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


def runs_when_the_folder_opens(task: dict) -> bool:
    """Tell whether the editor runs a task when its folder opens. Takes the task. Returns the answer."""
    run_options = task.get("runOptions")
    run_on = run_options.get("runOn") if isinstance(run_options, dict) else None
    return named(run_on) == "folderopen" if run_on else task.get("runOn") == "folderOpen"


_EDITOR_PLATFORMS = ("osx", "linux", "windows")
_OUT_OF_SIGHT = ("never", "silent")
_TASKS_OF_THEIR_OWN = (None, "$customized", "shell", "process")


def _truthy(value) -> bool:
    """Tell whether a setting's value counts as set the way the editor's JavaScript reads it. Takes the
    value. Returns False for false, 0, an empty string and null, True for anything else."""
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return value == value and value != 0
    if isinstance(value, str):
        return value != ""
    return value is not None


def hidden_from_the_task_list(task: dict) -> bool:
    """Tell whether the editor leaves a task out of its list of tasks to run. Takes the task. Returns the
    answer."""
    return _truthy(task.get("hide"))


def _presentation(scope) -> dict:
    """Return how one part of a task file says its terminal shows: its older echoCommand and showOutput,
    then presentation (or its older name terminal) over them, each only when it has the type the editor
    reads. Takes the part. Returns the settings it gives, as echo and reveal."""
    if not isinstance(scope, dict):
        return {}
    shown = {}
    if isinstance(scope.get("echoCommand"), bool):
        shown["echo"] = scope["echoCommand"]
    if isinstance(scope.get("showOutput"), str):
        shown["reveal"] = scope["showOutput"].lower()
    presentation = scope.get("presentation")
    if not _truthy(presentation):
        presentation = scope.get("terminal")
    if isinstance(presentation, dict):
        if isinstance(presentation.get("echo"), bool):
            shown["echo"] = presentation["echo"]
        if isinstance(presentation.get("reveal"), str):
            shown["reveal"] = presentation["reveal"].lower()
    return shown


def _out_of_sight(shown: dict) -> bool:
    """Tell whether terminal settings keep a task's run from view. Takes the settings. Returns True when
    the terminal does not come forward when the task starts, or the command it runs is not shown."""
    return shown.get("reveal") in _OUT_OF_SIGHT or shown.get("echo") is False


def keeps_its_terminal_out_of_sight(task: dict, task_file: dict) -> bool:
    """Tell whether a task runs out of sight: its own presentation hides it, or on some platform its
    terminal settings, read as the editor builds them, do — a task of its own takes its platform's block
    over itself, then whatever the task file sets for every task fills in what it leaves unset; a task of
    another kind reads only its own presentation. Takes the task and the task file it sits in. Returns the
    answer."""
    own_presentation = task.get("presentation")
    if isinstance(own_presentation, dict) and _out_of_sight(_presentation({"presentation": own_presentation})):
        return True
    if "customize" in task or task.get("type") not in _TASKS_OF_THEIR_OWN:
        return ("presentation" in task or "terminal" in task) and _out_of_sight(_presentation(task))
    filled = task.get("command") is not None or "dependsOn" not in task
    for platform in _EDITOR_PLATFORMS:
        own = {**_presentation(task), **_presentation(task.get(platform))}
        every_task = {**_presentation(task_file), **_presentation(task_file.get(platform))} if filled else {}
        if _out_of_sight({**every_task, **own}):
            return True
    return False
