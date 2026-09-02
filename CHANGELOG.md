# Changelog

All notable changes to this project are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

**What belongs in an entry.** An entry describes what someone *using* a release observes: new or
changed behaviour, flags, compatibility, and fixes they would notice. It does not describe internal
implementation — module layout, refactors, detector or rule internals, thresholds, the inputs an
analysis keys on, coverage gaps, or release-pipeline mechanics. A change with no user-visible effect
does not get an entry. For a security fix, state that the fix shipped and what it means for the
reader, not the mechanism or the weakness it closed.

## [Unreleased]

### Fixed
- **`saw fix` no longer deletes directories you excluded from scanning.** `exclude_dirs` says what
  is read, and nothing now infers from it that a directory may be removed — vendored code, fixtures
  and test corpora were being destroyed, with no copy kept.
- **Generated outputs are removed only when the lockfile accounts for the installed tree**, and are
  copied into the quarantine directory first, as everything else on that path already was.

### Changed
- **`saw fix` says that its removals happen in your working tree**, when the run happens rather
  than when a pull request is merged, and names the directory the copies were written to. The
  reference page says the same.

### Fixed
- **`saw audit` no longer withholds the credential-rotation all-clear because macOS protects one of
  its own directories.** Only a location inside an installed application counts against the
  verdict; a directory swept up while looking for applications, that turns out not to be one, is
  reported as something the run did not read and nothing more.

### Fixed
- **`saw audit` says how many locations it could not read, before listing them.** A long path used
  to push the count — and the other locations — out of the report, leaving neither. Each path is
  shortened in the middle for the same reason, and a location reached twice is named once.

### Added
- **`saw harden --take-back` removes the controls the command placed.** It removes only those, and
  reports anything it did not remove. A location holding anything is left as it stands.

### Fixed
- **`saw harden` reports a control as in place only on evidence it cannot be fed.** Neither what it
  reads to decide that nor which account it decides it for is influenced by the environment of
  whoever runs it, so a control that is in place stays visible and one that is not is never
  reported as though it were.
- **Raising a control to root no longer risks closing over something that arrived while it was
  briefly open.** If anything has, the location is handed back to you — unlocked, yours, and
  writable so you can clear it — and the run names it and does not pass, instead of reporting the
  location as untouched.
- **`saw harden --take-back` no longer reports a run as complete over a location it left open**,
  and says which locations to look at first.
- **`saw harden` recognises the operator whichever way privilege was raised**, and when it cannot
  establish who that is it says so instead of assuming. A control it cannot attribute to itself is
  reported as a lock held by another account rather than as an absent one, and neither command
  will open or remove it.
- **The lock never goes back on over something that arrived while it was off.** Every path that
  sets it, in both commands, now confirms afterwards that it closed over an empty location — asking
  first and not looking again is what let an arrival through — and takes it straight off again if
  it did not.
- **A location this command changed and could not finish with is handed back to you.** It used to
  be left read-only, so the file you were being told to go and look at could not be removed from a
  directory you own, and `--take-back` could not see what had been left behind.
- **Run again with `sudo` and a control held by another account on the machine is taken over**
  rather than refused with a reason that was not true of a privileged run. Without `sudo` it is
  named, and says so. `--take-back` still leaves it alone: it removes only what it placed.

### Fixed
- **`saw audit --verify` never reports a scan that did not clear a module as one that found
  nothing.** Only a scan that read the whole directory and found no markers clears it. A scan that
  could not start, could not finish, or could not read everything now says so and says why, names
  the modules it did not settle, and withholds the credential-rotation all-clear until it can. It
  used to report the weaker finding instead — whose own advice is to run `--verify`.
- **A module that was scanned and came back clean now says so** — and says what that does and does
  not settle — rather than repeating the advice to run the scan that had just cleared it.
- **Anything the audit could not read inside an installed application is named.** A module, a
  directory it could not list, or a location it could not enumerate at all used to produce nothing
  whatever — no finding, no count, no mention, indistinguishable from having looked and found
  nothing. Each is now named so you can go and clear it, and each withholds the credential-rotation
  all-clear until you have. Locking a file and locking the directory holding it are answered the
  same way, so neither is a way past the check.
- **A bound the audit hit is always reported**, including when it fell exactly on the last module
  of a directory, where it used to be reported as nothing.
- **A pipe or device named like an application module no longer stops the audit.** Reading one had
  no timeout, so anything able to write into an application's own directory could hang the run.
- **The same fixes on the host-artifact surface.** `--verify` there also reported a scan that blew
  up as the advice to run `--verify`, and described a directory it had not scanned as one where a
  content scan found nothing.

### Changed
- **`saw harden` no longer requires root.** Run as yourself it acts where it can, and names
  anything it did not take rather than stopping. Run again with `sudo` to act on the rest and to
  strengthen what is already in place; the result distinguishes a control root holds from one you
  hold and tells you which you have. Anything already in use is still left unchanged, and it still
  refuses while a running process holds code that is not on disk.

### Fixed
- **`saw audit` no longer reports the controls `saw harden` placed as a finding.** A location that
  holds a control is credited as one; a finding elsewhere reads as being outside it. An empty
  directory in one of these locations is no longer described as something it is not.
- **`saw harden` acts only where it was told to.** A location named relative to where the command
  happened to be run is refused rather than acted on, so it cannot reach a directory outside the
  machine-level scope it states. It creates the location it was aimed at and nothing above it, so
  a location named for something the machine does not have no longer gets built out for it — that
  location is named in the result instead.
- **A location that something else depends on is left able to be removed.** Acting there would have
  stopped an installed toolchain being uninstalled or upgraded, with an error naming nothing.
- **Running again with `sudo` now strengthens what you already hold.** It reported such a host as
  not protected, and advised against rotating credentials, while the controls were in place.

### Changed
- **`saw fix` now points at `saw fix amend` for a commit it cannot change.** Its review note sent
  operators to an external tool for the job `saw fix amend` does, and said `saw fix` "never
  rewrites history" — it does not change past commits, which is what it meant and what it now
  says. The note is shorter, and still states that the commit stays in any clone, fork or tag.

### Added
- **`saw fix amend` checks that the payload is actually gone before it moves anything.** Every
  other check it makes asks what changed; this one asks whether anything reported is still
  there. A result that still reaches a reported commit, or that still holds the reported content,
  stops the run — and because the check happens before any branch moves, a repository that fails
  it is left exactly as it was.

### Changed
- **`saw fix amend` clears every infected commit in one run.** It used to stop when more than one
  commit carried the payload, which left the repository infected after a run that had already
  established it could act. The stretch of history rewritten is decided by the oldest of them, so
  clearing several is the same rewrite as clearing one, and commits before that keep their
  identity. The shape of the history is unchanged: a merge stays a merge with its parents in
  their original order, its recorded content intact, and each commit keeps its own author.

  It stops without changing anything when a confirmed commit is on no branch it can reach, and
  when a later commit edited one of the reported files and that file still carries the payload
  there — replacing it would either miss the payload or discard that commit's work, so the run
  reports it instead. A commit is no longer required to be a merge to be replaced.

### Fixed
- **`saw fix amend` takes the payload and leaves the rest of the commit alone.** It used to
  rebuild the commit from its parents, which discarded everything else that commit contributed —
  a conflict resolution, an edit made while the merge was open, a file it deleted — so it refused
  in the cases that actually occur, including a merge that resolved a conflict and carried the
  payload. The replacement is now the commit's own content with only the reported paths put back,
  and those are the only paths that change.

  A correction is confirmed to have taken effect before the replacement is used, so a path that
  could not be matched is reported rather than counted as removed. File modes are kept, so an
  executable stays executable and a symlink stays a symlink. The message and the author are
  reproduced exactly, and a commit recording something a replacement cannot carry is refused
  rather than altered. If the reported content was already there before this commit, replacing
  this one does not remove it and the run says so.

### Changed
- **`saw fix amend` has its own reference page, with the caution first.** It states what the
  command needs before it will act, what it stops for, and what it leaves for a person to
  finish.

### Added
- **`saw fix amend` replaces past commits that still carry the payload and force-updates
  each branch they sat on.** That force-update is the fix. It does not open a pull request
  and it does not take `--branch`. The replaced commit keeps its original message. Tags and
  notes are not moved. If a remote branch cannot be read, nothing is force-updated. If the
  remote does not move, local branches are left as they stood. The previous objects remain
  until collected. Bare `saw fix` still only cleans the tip.

  It refuses before anything moves when the credential may not rewrite that repository, when the
  remote branches cannot be refreshed, when the repository is set to sign commits and no signature
  can be made, when the replacement would drop content the finding does not cover, or when the
  previous commits cannot be captured first. A protected branch is never force-updated: the
  amended history is published beside it under its own name and a person opens the pull request,
  and a protection rule that cannot be read is treated the same way. A replacement that changes
  commits it should not have is put back rather than pushed, and a branch that is moved and cannot
  be put back is reported as exactly that. There is no account-wide form: each repository is
  named, and a named path that does not exist is an error rather than a wider sweep.

  Signed history stays signed. Whether the replacement and the replayed commits are signed
  follows the commits being replaced, not only this clone's settings, so history signed elsewhere
  — by a merge made on the web, or on a machine that is not this one — is not quietly replaced
  with unsigned commits. A repository that needs a signature and cannot produce one refuses.

  A clone that does not have everything its remote branch has is refused rather than
  force-updated, so commits that exist only on the remote are not deleted unseen. Forks are
  counted rather than assumed. A run that examined no repository is not reported as success.

### Fixed
- **`saw fix --pr` publishes the cleanup branch; it does not overwrite a remote ref.** A
  branch that is not fast-forwardable is refused, not force-updated. `saw fix amend` is the
  act that force-updates.
- **`saw fix` no longer reports a working tree as clean when a merge finding is still live in it.**
  Files that still carry the payload are restored on the review branch. The merge commit stays;
  `saw fix` still never rewrites history. If it cannot tell whether those files still carry it,
  it does not treat the tree as clean.

### Changed
- **Operator documentation describes the verdict, not process status.**

### Added
- **`saw harden` creates host denials and only reports them as in place after a read-back.**
  It never touches a project's dependency tree. An unverifiable write is unknown, never success.
  A path that already has something in it is left unchanged. If a running process still holds
  code that is not on disk, it refuses until that process is captured. A denial that is in
  place is not reported as a drop artifact. It does not claim that one control protects
  anything else.

### Fixed
- **`saw harden` applies a control only at the location it named, and only when it can confirm that
  is where the control went.** Anything it cannot confirm is left as it was and reported, never
  counted as applied. The report does not say the control is in place when it is not.
- **A run that examined nothing on this machine is refused rather than applied.**
- **A leftover location after `saw harden` does not make credential rotation safe.** An audit still
  holds rotation until that location has been inspected.
- **A location a check could not read is no longer reported as a clean result.** Those checks
  used to return the same empty answer they return on a clean host. They now say the location
  could not be read, and the run is UNKNOWN rather than clean.

### Added
- **On a confirmed infection, `saw fix` also removes this repository's installed tree, generated
  build outputs, and lockfile.** On CI the lockfile stays. The host is not touched. A scan that
  did not finish does not change the tree.

### Added
- **A start-up item that runs something its name cannot account for is now reported.** The name and
  the path were both already read and never compared. Neither is suspicious alone — the
  contradiction between them is, and it is the shape an item takes when it borrows a familiar name
  to look routine.

### Fixed
- **Two host indicators that one command leaves behind no longer read as a live implant.** They are
  still reported, and credential rotation is still held — what changes is the claim: something staged
  here, rather than something is running here, which is what the advice to isolate and rebuild
  depends on.

### Fixed
- **A task set to run when a folder opens is no longer critical on that alone.** Running on open is
  what the setting is for, and ordinary project configuration uses it. It is now reported as
  something to review, and reaches critical only when the task also hides itself — legitimate
  auto-run tasks are common, ones that keep their own execution off the screen are not. Nothing
  stops being reported; the grade changes.

### Fixed
- **On a platform `saw` does not yet cover, checks no longer report that they found nothing.** Most
  of the start-up surface has no Windows implementation, so those checks returned nothing — the same
  answer they give on a clean machine — and a Windows run came back clean at exit `0` over a surface
  nothing had examined. Those checks now say the platform is not covered, the run says so once, and
  it treats credential rotation as unsafe until you have looked yourself.

### Added
- **`saw audit` now examines the code that running processes were handed.** A loader passed to an
  interpreter as an argument never touches the disk, so every check that reads files was looking in
  the wrong place — and that is the shape a real incident took. An audit now reports one when it
  finds it, holds credential rotation, and tells you to capture the process before you end it. It
  also says how many processes it was not permitted to read, and says so outright where the system
  will not hand arguments over at all, so a quiet result is not read as covering the whole machine.
  It reports; it never stops or ends anything.

- **A scan can now say `residue`.** A cleanup that backed a file up and then left it unchanged was
  reported as either clean or infected, and both were wrong: nothing new executes there, but the
  file is not what the project would carry. `residue` is the weakest verdict, so it can never mask
  a suspicious or infected one, and it does not fire the CI gate — a scan that finds only residue
  still exits `0`, and says so rather than reporting a clean bill of health. A cleanup that finished
  leaves the tree clean, as before.

- **`saw audit` now reads the JavaScript an installed application loads.** That code belongs to the
  application, not to a dependency — no manifest lists it and no lockfile covers it, so
  reinstalling dependencies never reached it, and it is where a cleanup can be undone from. A
  module it flags
  is reported so you can check it against the publisher's copy; `saw audit --verify` looks harder at
  one, and a confirmed result there is treated as an active foothold that holds credential rotation.
  Applications are found by their layout rather than by a list of names, a tree reachable under two
  paths is read once, and what the walk did not reach is reported rather than counted as clean.

### Changed
- **A check your machine would not let finish is no longer reported as a check that found
  nothing.** A missing tool or an unreadable path used to produce silence, and silence read as a
  clean result. Those checks are now listed under **Not checked**, naming what stopped each one,
  and whatever they did manage to establish is kept. One of them no longer ends the audit — the
  rest still run.
- **`saw audit` exit codes now cover a check that did not finish.** One that reads the start-up
  surface exits `3`, because the surface was not established and rotation is not safe; any other
  exits `2`, the existing meaning of a run that could not complete. Neither can leave the run at
  `0`.

### Fixed
- **An unreadable file inside a start-up directory is no longer reported as a clean directory.** The
  audit certified that it could list those directories without certifying the records inside them,
  so a file it could not read produced no finding at all and a host could report "persistence
  surface enumerated and clean" at exit `0` over a start-up item nobody had read. Every record is
  now certified alongside its directory, including ones reached through a symlink and ones a
  directory deeper.
- **A global git configuration that git itself cannot read is no longer treated as no configuration
  at all.** A configuration file inside a directory the audit may not inspect was reported as
  absent, so a host with an entry that runs a command on every git operation could exit `0`.

- **A scan now says that it looked at the working tree only**, and names what it did not look at —
  earlier commits, other branches and tags. Any of them is one command away from being on disk
  (`git checkout <rev>`, `git clone --branch <tag>`), and a fix is a forward commit on one branch, so
  a file cleaned there may still be served from a tag. This is a coverage note: it reports what was
  not examined and does not change the verdict or the exit code.
- **`saw fix` documentation states what a fix does and does not remove** — it cleans the tree with a
  forward commit and never rewrites history, so clearing what remains in history is a separate
  decision, with what that involves spelled out.

### Fixed
- **Guidance after a suspected wipe no longer promises that missing data is recoverable.** Whether
  anything survives depends on which wipe variant ran, and a host-side audit cannot tell — so the
  incident runbook and the wiped-home finding now state that as a condition rather than asserting
  it. Both still tell you to image first, because imaging is what preserves the case where recovery
  is possible, and the step now names `saw fix` among the writes to hold off until then.
- **The runbook now says what to do when neutralization cannot be confirmed** — image first and
  rotate anyway, rather than leaving the credentials live: the trigger stays armed for as long as
  they are valid, and a wipe against an imaged host costs nothing.
- **The issue `saw` opens automatically now points at remediation that exists.** It previously told
  the reader to run a cleanup script that this project has never shipped. It now points at
  `saw fix --pr`, and says plainly that the issue closing means the repository scans clean — not
  that a machine which ran the code is clean.
- **`saw audit` no longer reports active host persistence over a single ordinary file.** Where a
  temporary directory is reachable under more than one name — which is normal on macOS — one file
  could be counted twice and treated as corroborating itself, producing the isolate-and-rebuild
  runbook and exit `3`.

### Changed
- **The same kind of artifact in more than one place is now described as staging rather than as a
  live implant.** Rotation stays gated and the exit code is unchanged; what changes is what you are
  told to do — inspect the locations, and rebuild only if a scan or your own inspection finds
  payload code.
- **`saw audit --verify` content-scans every corroborated location**, not only the first, and a scan
  that finds nothing — or fails — can no longer lower a finding.

## [0.7.0] - 2026-08-25

### Added
- **`saw fix --branch <name>` fixes a branch other than the repository default** (repeatable). The
  named branch is left untouched — the fix is prepared on `saw`'s own branch for you to review, as
  it already was for the default. Naming a branch that does not exist is refused with the reason,
  rather than falling back to the default.
- **`saw` now detects the code loader by what it does rather than by how it is written**, so a
  repacked variant is caught as well as the original. A repository carrying one is reported as
  infected and `saw scan` exits `1`, where such a file could previously be reported as only
  suspicious.
- **`saw fix` can now remediate the files this detects**, restoring the affected config to its
  earlier contents instead of leaving them for manual review.
- **When a loader is found in a working tree on your own machine, `saw scan` says so plainly** — it
  may already have run, so it tells you to treat the host as compromised until `saw audit` says
  otherwise, and not to rotate credentials first. A scan of a remote repository never says this.

### Fixed
- **`saw fix --pr` no longer stalls on a repository whose `security/auto-clean` branch is already
  taken.** The fix branch is now named after the branch it targets — `security/auto-clean-main`,
  `security/auto-clean-develop` — so each base gets its own, and a name held by unrelated work steps
  to a numbered sibling instead of failing. A branch an earlier run created is reused rather than
  duplicated.
- **A push refused by a repository rule is reported as a rule refusal, not as missing access.** It
  no longer sends you to check permissions, and no longer attempts a fork that would meet the same
  rule.

### Changed
- **`saw discard` removes every `security/auto-clean` branch it finds**, including the plain one left
  by earlier versions.
- **The container image no longer ships `pip`.** `saw` installs nothing while it runs. Running `saw`
  is unaffected; if you extended the image by installing packages inside it, build a derived image
  that brings its own installer.
- **`config/security.yml` is now read only for the directory it belongs to.** Acting on a path
  outside the current directory no longer uses that directory's config; name one with `--config` to
  apply it to any other target. A bare `saw scan` and an explicit `--config` are unchanged.
- **`saw` states which config it loaded and how many allowlist rules are in effect**, and states
  when it declined to use one.

### Security
- **The container image is rebuilt on a current base**, so it picks up the operating-system security
  updates published since the last release.

## [0.6.3] - 2026-08-21

### Added
- **Documented where the report goes when a scan is too large for the terminal.** A big sweep prints
  a summary and writes the full per-finding report to a file; the reference now says where that file
  lands with and without `-d`, that its evidence is redacted like any copy on disk, and that a
  temporary one is left for your operating system to clear rather than deleted by `saw`.
- **The documentation is now published as a searchable, versioned site** at
  <https://saw-docs.ndevuspace.com>, with light and dark themes. Every page carries its own summary,
  a shared link previews with a proper card rather than a bare URL, and the site describes itself to
  search engines so its pages can be found without going through the repository first. Because `saw`
  ships pinned releases, each release keeps its own copy of the docs, so a pinned install can read
  the pages that describe the version it actually has; `latest` tracks the current documentation.

### Changed
- **The CLI reference is now one page per command** instead of a single long page — `saw scan`,
  `saw fix`, `saw audit` and the rest each have their own page, alongside pages for remote
  targeting, report sinks and credentials. Existing links into the old page are repointed, and the
  content is unchanged.

### Fixed
- **A `--config` file that does not exist now fails the same way in every command.** `saw scan`
  reported it as a Python traceback; the others each printed their own wording. All five say the
  same thing and exit without scanning.
- **`saw hook` no longer lets a freshly-cloned repository control your terminal.** Scan-on-clone
  printed the names of the files it flagged exactly as the repository wrote them, so a crafted file
  name could erase the warning it was printing.
- **Filed security issues can no longer be reshaped by a repository.** The target and each file name
  in the issue's table are neutralised, so a crafted name cannot turn a row into a link or shift the
  table's columns.
- **`saw fix --remote` no longer reports success for a repository it could not fix.** When the
  credential cannot reach a repo, or the clone fails, the run now exits non-zero and says the repo
  needs review — previously it printed the failure but exited 0, so a script checking the exit code
  believed the repo had been remediated.
- **`saw audit --verify` no longer treats a clean content scan as reassurance.** Finding nothing
  inside an unusual folder does not make it safe — a staging tree holds ordinary packages, and the
  code that used them can be gone from disk — so the folder keeps the same "verify this is yours"
  standing it had before the scan, and the report says how many files it could not read (archives
  and binaries are not opened). A scan that finds worm markers still escalates as before.

## [0.6.2] - 2026-08-17

### Changed
- **`-h` on any command now says what the command is for and shows how it is run.** Every
  subcommand's help opens with a short statement of its purpose — including the safety-relevant
  part, such as that `saw scan` is read-only and its exit code is the verdict, or that `saw fix`
  prepares a branch and pushes nothing on its own — and ends with a handful of real example
  invocations, the everyday one first. The examples are the ones from the CLI guide, so the
  terminal and the documentation agree.

### Fixed
- **`saw hook -h` no longer lists an internal `run` entry**, which appeared as a row reading
  `==SUPPRESS==` and was never meant to be typed by hand.
- **`saw audit` no longer says rotating credentials is safe while telling you to rotate last.** When
  an unusual file or directory is found, the report asks you to confirm it is yours — and it now says
  the rotation all-clear depends on that answer, instead of stating it unconditionally a few lines
  above. Nothing changes for a clean run, for a real incident, or for the exit code.

## [0.6.1] - 2026-08-17

### Changed
- **Local security hygiene says what it found and what to do, and links the rest.** Findings are a
  sentence and a fix; the list of what the audit does not scan moved out of every run and into the
  documentation, reached by a link the report still prints. The caveat that a clean audit is not a
  clean bill of health stays on screen.
- **The CI gate `saw guard setup` installs now pins every action it runs to a commit SHA**, not just
  the scanner. A tag can be repointed at different code after you review it; a commit cannot — and
  the gate job holds write access in your repository. Re-running `saw guard setup` on a repository
  that already has the gate still rewrites only the scanner pin, so an existing workflow is not
  reformatted; the new pins apply to gates installed from now on.
- **The cached-credential finding is much shorter.** It keeps the parts that change what you do —
  that deleting a token a helper is actively serving will log you out, and to confirm you do not rely
  on HTTPS auth before removing one — and drops the background explanation of why storage location
  is not the risk. No check, verdict or exit code changes.

### Fixed
- **`reports_dir` in your config now works.** Setting it is enough to get the report bundle
  written — previously it was silently ignored unless you also passed `-d/--reports-dir`, which
  then overrode it, so the setting could never take effect. `STAYAWAKE_REPORTS_DIR` was ignored the
  same way, which is why a scan inside the container image did not write to the directory the image
  configures for it. Writing reports is still opt-in: with no flag, no environment variable and no
  setting, a scan writes nothing.

## [0.6.0] - 2026-08-16

### Added
- **The home-wipe detector catches four shapes it used to miss**: deleting the home directory through
  a variable it was first assigned to; walking home with `listdir`/`scandir`, which is the most
  common way to do it in Python; splitting the walk and the delete into two functions that are wired
  together at a call site; and deleting with `shutil.rmtree`, Python's standard recursive delete.
- **`saw audit` now checks every location Node loads a global module from**, not just
  `~/.node_modules`: also `~/.node_libraries` and the install prefix's `lib/node`, resolved from your
  environment on macOS, Linux and Windows alike. A module tree staged in any of them used to be
  invisible while the same tree one directory over was reported. All are graded identically,
  including the rule that only a directory counts.
- **An evil-merge finding now says whether the introduced content is still in your working tree.**
  A merge that smuggled a payload and one whose payload was deleted afterwards need different
  responses. A file that changed since the merge is reported as **unverified**, never as removed —
  the introduced lines may still be inside it — and a deleted path still notes that the content
  remains in history and in any fork.
- **`saw scan` now catches a merge commit that was edited by hand where git merged cleanly.** If a
  file merged without conflict, git's result is fixed — a different result means somebody changed it
  while merging, which no branch's diff shows and no pull-request review renders. This is reported
  on its own, where previously it was missed unless the edit also matched a signature.

### Changed
- **Findings say the same things in fewer words.** The audit's guidance was carrying background a
  developer does not need mid-incident; every claim, warning and instruction is unchanged, including
  the credential-rotation warning, which still appears at every point where you might rotate. The
  longest finding lost more than half its length.
- **`saw scan` no longer prints a matched payload as clean, pasteable text.** A match in a scanned
  file is now shown as a fingerprint with a bounded preview — long enough to recognise a false
  positive, not a copy of the payload. Findings whose evidence is saw's own explanation are shown in
  full, unchanged, and `--json` still carries the complete snippet for tooling.
- **The container image now installs its dependencies from a hash-pinned lock** rather than
  resolving them fresh at build time. Two builds of the same commit now produce the same image, and
  a package whose contents do not match the recorded hash is refused rather than installed. This
  does not change what `pip install stayawakebot` gives you — the package's own dependencies are
  unchanged and remain unpinned.
- **What matters most is now listed first in every report.** `saw audit` shows a live foothold above
  a credential exposure above everything else, instead of the order the checks happen to run in; and
  the saved report bundle lists infected repositories before suspect and clean ones, which it did not
  order at all before. The scan table is unchanged — the rest now matches it.
- **A scan no longer takes every CPU core.** It leaves one free, so the machine stays responsive
  while a scan runs, and it sizes itself from the CPUs the process is actually allowed to use — so
  running inside a container with a CPU limit no longer starts workers for the host's cores. Pass
  `-j N` to choose the number yourself; that is unchanged.
- **The incident runbook now offers to image the disk before the step that rebuilds the host**, and
  says when deleted content is still recoverable. Rebuilding, and ordinary continued use, overwrite
  it.
- **`saw audit` now prints the recommended fix for an unverified persistence surface.** It previously
  reported that rotation was unsafe without printing what would resolve it.

### Fixed
- **The package works on Python 3.11 again.** A report-rendering module could not be imported
  there, so anything that printed a finding failed. Python 3.12 and later were unaffected.
- **Saved reports no longer keep advisory evidence in full.** Findings were redacted before writing;
  advisories were not, so the saved bundle held text the sink promised it would not.
- **`saw scan` no longer lets a scanned repository control your terminal or your CI log.** The
  matched snippet and the file path were printed unchanged, so a crafted file name or file content
  could retitle the window, clear the screen, or emit text a CI system reads as its own
  instructions. Both are now neutralised while still being shown, matching the fix already applied
  to `saw audit`.
- **The container image is published again.** The 0.5.2 image was not pushed: its digest-pinned
  base carried newly-fixed vulnerabilities, and the release's vulnerability gate correctly
  refused to publish. The base image is updated. `pip install` was unaffected — only the
  container is new here.
- **`saw scan` no longer calls a project infected because two unrelated things appear in one file.**
  A file that listed your home directory in one place and deleted something entirely different in
  another was reported as a home-directory wipe — a dotfile manager, or an editor bundle whose
  documentation happened to contain both. The two now have to belong together.
- **`saw scan` no longer reports ordinary HTTP-parsing code as infected.** Writing the DEL character
  by its numeric code is ordinary JavaScript, so any RFC 7230 control-character table matched a
  malware loader fingerprint at the tier that asserts malware — failing a CI gate on a vendored
  bundle. The fingerprint now requires the characters to be assembled and then executed nearby, which
  is what distinguishes a string shuffler from a character table. Real loaders are detected exactly as
  before.
- **`saw audit` no longer reports a hardened host as a compromised one.** Prevention guidance in
  circulation tells operators to make `~/.node_modules` a non-directory so a worm cannot stage there.
  The audit described that location as "an npm tree" but accepted anything present, so following the
  advice created the very indicator, which could combine with one other weak signal into a warning
  that withheld the credential-rotation all-clear. A real directory there is reported exactly as
  before.
- **The explanation offered for that finding named a command that cannot produce it.** It blamed a
  manual `npm install` in your home directory, which creates `~/node_modules` — without the dot — so
  the one route a user had to clear the finding themselves pointed at a path the audit never checks.
- **`saw scan` no longer treats code written in a comment as code that runs.** A file was reported as
  obfuscated for containing a comment such as `// never use eval() here`, or a commented-out line —
  a warning against the thing read as the thing. Code is still read exactly as before, including
  constructs assembled inside string literals.
- **`saw scan` now sees code written inside a template literal's `${...}`.** Anything spliced into a
  template was being read as text rather than as code, so a decoded payload handed to a shell that
  way went unreported while the same payload joined with `+` was caught. Both are now detected, and
  ordinary templates — building a URL, a command with a variable, a styled component — are still
  clean.
- **`saw scan` no longer reports ordinary front-end code as obfuscated.** Reading a JWT or a data URI
  with `atob` was treated as executing code, and any list of nine or more numbers — icon sizes, a
  colour table — was treated as a smuggled string. Both now need the step their names imply: a decode
  counts when the file also runs a command, and a number list counts when something consumes it as
  character codes. Packed loaders and character-code strings feeding `eval` are detected exactly as
  before.
- **The release pipeline blocked on vulnerabilities it was configured to ignore.** The container
  vulnerability gate is meant to stop a release only for a fixable critical or high finding, but it
  was rejecting releases over low, medium and unrecognised ones — the `0.5.2` release was blocked
  with no critical or high finding at all. The gate now applies the severity it documents, and the
  full scan report is still published for every release.
- **`saw scan` no longer reports an ordinary merge as an attack when the branches have no common
  ancestor.** Merging two unrelated histories has no clean three-way merge to compare against, and
  every file the other side brought in was being reported as introduced by the merge — one such
  merge produced 18 findings and marked the repository infected. Such a merge is now judged on its
  content alone, and a merge that introduces no new content is not a finding.
- **`saw audit` now finds shell start-up files that are not kept in your home directory.** A
  configuration under `$ZDOTDIR`, or a `fish`/`nushell` config in `~/.config`, was neither examined
  for a planted start-up line nor counted when the audit decided whether it had a persistence surface
  to certify — so on those setups a line that runs on every new terminal went unreported, and an
  in-use account could be described as having nothing to examine. `fish`'s `conf.d` drop-in
  directory, which is sourced on every start, is now read as well.
- **`saw audit` no longer reports a host whose persistence locations are all missing as "enumerated
  and clean".** When every location the audit certifies is absent, nothing was actually examined, so
  the run now ends **UNKNOWN** and withholds the rotation all-clear (exit `3`) instead of stating that
  rotating credentials is safe. **This is the expected state on a new account, a container or a CI
  image** — the report says so, and says what to check; it is also what a destroyed home directory
  looks like, and the two cannot be told apart from disk. Windows is unaffected.
- **`saw audit` no longer cuts a finding's detail or its recommended fix short.** Long text was
  silently truncated at a fixed length, so a report listing several unreadable locations named only
  the first two and the credential-rotation warning could stop mid-sentence.
- **`saw audit` now certifies the fish shell's startup file, which it already read.** A `fish`-only
  account was scanned for a planted start-up line and then described as having no shell startup file
  at all.
- **`saw audit` no longer describes a surface it read as one it could not read.** The verdict, the
  scope note and the report's opening line said a location had been unreadable even when every
  location had been read and none existed, sending a reader looking for something that was not there.

### Security
- **`saw audit` no longer lets a discovered file path reach a copy-pasteable command unchanged.** One
  removal command named the configuration file it had found, and that name is not always chosen by
  you — so a crafted one could put terminal control sequences, or text a CI system reads as its own
  instructions, into a block you are invited to paste. The name is now neutralised while still being
  shown, and the command stays usable.

## [0.5.2] - 2026-08-14

### Added
- **A security policy** (`SECURITY.md`) with a private reporting address, so a vulnerability in the
  scanner can be reported without opening a public issue. **saw@ndevuspace.com** is also now the
  contact for commercial licensing and the package's author address.

### Changed
- **The README now leads with what `saw` is for** — hunting self-propagating supply-chain packages —
  and with `saw guard`, which writes and maintains the CI gate for you. The uptime sentinel is
  documented further down, since it is independent of `saw` and shares only the packaging.

### Fixed
- **The README's CI gate example used an input the Action does not accept** (`fail-on-findings`),
  so the line was silently ignored by anyone who copied it. The example is now a working
  configuration taken from a repository running it, with every action pinned by commit SHA.

### Security
- **`saw audit` no longer lets a filename it discovered control your terminal or your CI log.** Names
  in world-writable directories are chosen by whoever wrote the file, and the audit report printed
  them unchanged — so a crafted name could clear the screen, retitle the window, scroll a real
  finding out of view, or emit text a CI system reads as its own instructions. The report now
  neutralises those sequences while still showing the name. Copy-pasteable commands are unchanged.

## [0.5.1] - 2026-08-14

### Fixed
- **`stayawake-health-check` did not perform its checks unless `--fail-on-unhealthy` was passed.**
  A run without the flag reported success without contacting anything, so scheduled monitoring
  invoked that way recorded no results — re-check your coverage. The check now always runs, and the
  flag decides only the exit code.
- **`saw audit` now judges a start-up program by who signed it, not merely by whether its signature
  is intact.** Some binaries were accepted as properly signed when they should not have been, and
  separately, genuinely signed third-party applications could be reported as unsigned — making
  ordinary software look unaccountable. Both are corrected.
- **The README's quick-start scan command did not work.** It passed `--local`, a flag removed in
  0.1.6 — local is the default and `--remote` is the scope toggle — so following the README produced
  `unrecognized arguments: --local`. The README now leads with the security sentinel and shows
  commands that run.
- `saw audit`'s scope note no longer refers readers to a document that is not published.

## [0.5.0] - 2026-08-14

### Fixed
- **`saw audit` no longer misses a start-up entry whose interpreter is capitalised, or whose payload is named after one.** An entry running the standard python.org build of Python — whose executable is capitalised — was reported as nothing at all, however suspicious its payload; and a payload file named after an interpreter, such as `node.something.js`, was never read for content. Both are fixed, and a container command written with different capitalisation is again recognised as running elsewhere rather than on this host.
- **`saw audit` no longer stops reading a start-up script partway through, and no longer reports an agent that creates a temporary file as active persistence.** A start-up entry could contain shell that caused the rest of it to go unexamined, so anything after that point was never reported. Separately, an entry that made a temporary file in the ordinary way — the idiom stock system scripts use — could be reported as active host persistence, withholding the rotation all-clear and exiting `3`. Both are fixed, and `saw audit` now also reports payloads run through a shell trap or a process substitution.
- **`saw audit` no longer reports ordinary system agents as host footholds, and no longer misses a multi-line start-up script.** An agent running `tar`, `sort`, `du` or a config-file service with a `-c` option could be reported as active host persistence — withholding the rotation all-clear and exiting `3` — while a start-up entry whose shell script spans several lines was reported nothing at all. Both are fixed, and entries launched through `env`/`sudo` wrappers are now read correctly rather than skipped.
- **`saw audit` now catches a start-up entry that runs a scratch-directory payload with no punctuation in front of it**, such as a systemd `ExecStopPost=/bin/sh -c '/tmp/x &'`. It was reported only when a shell operator preceded the path.
- **`saw audit` no longer reports a start-up entry as an unattributable foothold on ordinary code.**
  A shell-shaped check was being applied to payload text written in other languages, where the same
  punctuation is routine — a JavaScript template literal, a default value, a comment. Signed,
  package-installed software could be reported as active host persistence, which withholds the
  rotation all-clear and exits `3`. Detection of the real shapes is unchanged, including start-up
  entries that run code from a world-writable scratch directory.
- **`saw audit` now says that it does not look for Windows start-up entries.** Persistence
  enumeration covers macOS and Linux user-scope locations only, so on Windows the audit finds no
  start-up entries because it examines none — not because there are none. It previously reported that
  silently, which reads as a clean host. The scope note names the gap on every platform, and on
  Windows the report no longer claims to have read a persistence surface. Presentation only: no new
  finding, and the verdict and exit code are unchanged.

- **An audit check that could not be completed no longer looks like an ordinary review note.**
  When `saw audit` cannot fully read the persistence surface it withholds its all-clear and says so
  — but that "could not establish this" state was rendered identically to a low-priority nudge, so a
  run that deliberately declined to certify could be read at a glance as a clean one. It is now
  visually distinct from both a nudge and an act-now warning. Audit rows also align consistently,
  which they previously did not across the two markers.
- **`saw scan` no longer reports INFECTED on published, benign packages.** A loader fingerprint
  collided with ordinary minified code, so vendoring a large published bundle — or running
  `--deep` on a project that depends on one — could fail your scan with an infected verdict and a
  non-zero exit. If a scan failed on a dependency you had no other reason to doubt, re-run it. The
  detection that catches this worm family is unchanged, and remediation is unaffected: a partially
  cleaned file that still carries loader code is still refused as "fixed".

### Added
- **A new confirmed indicator for the same worm family**, covering a marker the earlier fingerprints
  missed.

## [0.4.1] - 2026-08-11

### Fixed
- **`stayawake-health-check` failed on startup instead of running its checks.** If you run it on a
  schedule, its results were not being recorded — re-check your monitoring coverage. It now runs
  normally.

### Removed
- The `--reports-dir` flag on `stayawake-health-check`. The sentinel has written no report files
  since 0.1.8, so the flag had no effect.

### Changed
- **The availability status issue is now filed only where you configure it.** Set
  `settings.alert_repo: "owner/name"` in the health config; there is no default. With it unset no
  issue is written, while the check still runs, still prints results, and still sets its exit code.
- Documentation reorganised: the public repository carries product documentation. Install, usage,
  configuration, the CLI reference and licensing are unaffected.
- `saw audit` states the boundary of what it examined, so a clean result is not mistaken for a
  whole-host all-clear.
- This changelog now follows the Keep a Changelog standard. Released versions, dates and compare
  links are unchanged.

### Security
- Bumped the pinned self-scan engine used by the CI gate and the release self-scan to current `main`,
  so both validate against the same scanner that ships.

## [0.4.0] - 2026-08-04

### Added
- **`saw audit` reports whether credential rotation is safe**, and exits `3` when it is not, or could
  not be verified. `3` is additive and distinct from infected (`1`) and error (`2`); every existing
  zero/non-zero consumer still fails safe.
- **`saw audit` reports start-up entries it cannot attribute to installed software**, and background
  agents that re-run on a schedule — including ones whose network destination is otherwise ordinary.
  Disabled on ephemeral and CI hosts.
- **`saw scan` detects payloads that delete the user's home directory**, reported distinctly
  according to whether the deletion is recoverable, since that is the first question after a wipe.
  Covers POSIX shells, Windows batch and PowerShell.
- **`saw fix` can recover a file introduced by an evil merge.** The recovered version is never
  applied automatically — it lands as a review-required change the operator must approve.
- `saw scan` clean output notes that a repository scan is not a host all-clear.

### Changed
- Evil-merge findings are graded by the strength of their corroboration; the strongest are now
  reported as confirmed rather than suspicious. The same merges and paths are flagged as before.
- An evil-merge finding now gives history guidance — naming the commit and the files it introduced —
  rather than offering a file edit. `saw fix` never rewrites history.
- Where environment affects how a destructive finding should be read, the finding says so. Severity,
  verdict and exit code never vary with environment.

### Fixed
- `saw fix` no longer reports a repository "already clean" when its only findings were heuristic. It
  lists them and defers to review. Exit code unchanged, and heuristics are still never auto-fixed.

## [0.3.1] - 2026-08-03

### Fixed
- `saw hook` clone and pull warnings state explicitly what to avoid until the code is trusted, and
  show progress so a scan never looks stuck.

## [0.3.0] - 2026-08-03

### Added
- **`saw hook` — scan on clone.** `saw hook install` seeds git's template directory so future clones,
  pulls, branch switches and rebases are scanned before you install dependencies, build, or open the
  repository in an editor. A clone scans the full tree; an update scans only what changed. It is
  read-only and offline, warns rather than modifies, and can never break a git command. It uses the
  packaged signatures and your own allowlist — never one supplied by the repository being scanned.
  `saw hook uninstall` reverses it, `saw hook status` shows state, `SAW_HOOK_DISABLED=1` disables it
  per shell, and `SAW_HOOK_TIMEOUT` (default 60s) bounds it — a scan that times out reports the tree
  unverified, never clean.

## [0.2.0] - 2026-08-03

### Added
- **`saw scan -j/--jobs N` scans concurrently.** A multi-repository sweep scans several repositories
  at once, and a single large repository splits its files across workers. The default is `auto` — a
  small scan stays sequential, a large one uses one worker per core. `-j 1` forces sequential;
  `settings.jobs` sets the default and `settings.parallel_min_files` the floor. Results are
  byte-identical whether run with one worker or many, a failed worker still fails the scan closed,
  and `Ctrl-C` stops in-flight work immediately.
- `saw fix` and `saw guard` accept `-j/--jobs N` for multi-repository sweeps, with the same defaults
  and guarantees. `saw audit` is excluded — it has no multi-repository sweep.

### Changed
- **Scans are substantially faster with identical results** — roughly 1.9× on a 2,000-file tree, and
  it compounds with `-j`. No new flags.
- Scan progress is a live board when running concurrently. Piped, CI and `--no-stream` output is
  unchanged.

## [0.1.19] - 2026-08-02

### Changed
- **GitHub App authentication works on a base install**, with every install method; the optional
  `pyjwt[crypto]` extra is no longer needed and has been removed.
- `saw auth` output is formatted consistently with `saw audit`.

### Fixed
- A GitHub App now works across every account and organisation it is installed on, not only the
  personal account.

## [0.1.18] - 2026-08-02

### Added
- `saw guard setup` installs a complete CI gate: it scans, opens a single rolling fix pull request on
  an infected verdict, and raises a self-closing issue when the pinned scanner drifts.

### Changed
- The App registration flow binds an anti-CSRF nonce.
- Push-failure messages distinguish a bad credential from a missing permission.
- Untrusted paths are sanitised when displayed.

## [0.1.17] - 2026-07-31

### Added
- `saw auth app register` — register and manage a StayAwakeBot GitHub App.
- `saw doctor` reports GitHub App readiness.

### Fixed
- `saw auth` no longer crashes on a default install without the optional App extra.
- A repository-access denial is reported as such, rather than as missing write scopes.

### Security
- The GitHub App private key is no longer written with a window in which it is readable by others.

## [0.1.16] - 2026-07-23

### Changed
- A long result no longer floods the terminal. Lengthy scans show a summary dashboard on screen and
  write the full detail to a report file, whose path is highlighted.

## [0.1.15] - 2026-07-21

### Added
- `saw scan --deep` content-scans installed dependency code. Opt-in, because it adds time on a large
  dependency tree.
- `saw scan` tells you how to fix a flagged dependency, not just that it is flagged.
- `saw audit` detects a cached GitHub credential on Linux and Windows, not only macOS.
- `saw audit` flags two further editor auto-execution surfaces.

### Changed
- `saw audit`'s cached-credential finding explains what it does and does not mean, rather than
  implying the credential should be removed.

### Fixed
- Base64 tokens, key arrays and inlined assets are no longer flagged as packed payloads.
- A non-regular file in a scanned repository can no longer hang a scan.

### Security
- `saw`'s own file write and delete paths are hardened against symlink write-through.

## [0.1.14] - 2026-07-20

### Added
- `saw guard check` verifies a repository's CI gate; `saw guard setup` installs or updates it.
- `saw audit --verify` content-scans a suspicious host artifact.
- `saw scan` flags a repository that ships a write-redirect symlink.

### Changed
- `saw guard check` and `saw guard setup` discover and sweep repositories like `saw scan` and
  `saw fix`.
- `saw audit` right-sizes its incident-response guidance to the evidence, and describes weak
  indicators honestly rather than accusingly.
- `saw audit`'s report is easier to read.

### Fixed
- `saw guard --remote` no longer blames your token when a repository simply has no CI.
- `saw guard setup --pr` opens pull requests instead of silently doing nothing.
- `saw guard` recognises a gate installed by any mechanism, and no longer overwrites an existing one.
- `saw audit --repo` no longer reports a protected repository as unguarded.
- `saw guard` is documented alongside the other commands.

## [0.1.13] - 2026-07-15

### Added
- The scanner recognises further dynamic code-execution forms, reported as heuristic signals so they
  inform without failing CI or triggering remediation.

### Fixed
- `saw fix` no longer reports a fix it did not make when commit signing fails.

## [0.1.12] - 2026-07-15

### Added
- `saw fix` shows per-finding manual-review guidance rather than only a count.

### Security
- Updated the container base image for a fixable CVE, so the published image builds again.
- `saw fix` recovery no longer drops legitimate code that shared a line with a payload.
- Hardened what `saw fix` recovers from, and the check that the result is payload-free.

## [0.1.11] - 2026-07-12

### Added
- A first-run welcome, plus a `saw intro` tour.

## [0.1.10] - 2026-07-11

### Fixed
- `saw fix --pr` and `--remote` work under GitHub Actions with the default `GITHUB_TOKEN`.

## [0.1.9] - 2026-07-10

### Changed
- Relicensed to AGPL-3.0-or-later with a commercial option, from v0.1.9 onward. Releases up to and
  including v0.1.8 remain MIT.

## [0.1.8] - 2026-07-10

### Added
- Dependency CVE advisories as part of a plain scan, never gating.
- `saw db update` and `saw db status` — an offline advisory corpus with integrity checking.
- Dependency auditing across several more ecosystems, including PyPI, with version-range matching for
  substantially wider coverage.
- Audits the installed dependency tree, not only the lockfile, and detects tampered installed Python
  packages.
- `saw scan -x`/`--external` — the one opt-in that leaves the offline sandbox.

### Changed
- Python virtual environment directories are treated as generated context, like `node_modules`.
- Repositories with no dependency files scan about 10s faster.
- `saw audit` streams progress like `saw scan`.
- The CLI guide was rewritten for scannability.

### Removed
- The availability sentinel's file-based reporting.

### Fixed
- A stale advisory cache no longer reports as tampered.
- An editor auto-run setting is matched against its real value.

### Security
- `saw scan` fails closed when a target cannot be scanned; it previously failed open.
- Fixed a pathological regular-expression case in which a crafted repository could hang the scanner.
- Added detection for malicious upstream dependencies, planted OS-service persistence, self-hosted
  runner persistence, planted or impersonated CI workflows, malicious npm lifecycle hooks, AI agent
  auto-run configuration, host drop-file artifacts, invisible-character concealment, and the known
  worm's exfiltration and persistence stage.
- Opt-in build-output scanning.
- Incident-response guidance rotates credentials last.

## [0.1.7] - 2026-06-30

_No user-facing changes were recorded for this release._

## [0.1.6] - 2026-06-30

### Added
- `saw fix` — remediate on a branch, with `--pr` to publish; `saw discard` — undo a fix.
- Discoverable remote targeting, and result presentation for large fleets.

### Changed
- `saw scan` is read-only: detection only.

### Removed
- `saw scan --fix`, `--apply` and `--pr` — remediation is now `saw fix` and `saw discard`.
- `saw scan --local` and `--local-only` — local is the default, and `--remote` is the scope toggle.

### Security
- Remediation recovers a payload-carrying file from its last clean committed version, or defers to
  manual review with the exact command to run. It never edits a source file surgically, so a fix
  cannot leave broken code. Originals are backed up, and a fix pull request aborts rather than open
  over a still-infected tree.
- The GitHub API verifies TLS against a bundled CA set, API errors go to stderr only so they never
  pollute a report, and the API is pre-flighted before any push.

## [0.1.5] - 2026-06-29

### Added
- A readable terminal report; `saw scan` is terminal-first.

### Changed
- `saw scan`'s exit code is the verdict, unconditionally.
- Security reports are no longer committed into the repository.

### Removed
- The `saw run`, `saw report` and standalone `saw alert` verbs. `scan` renders to the terminal and
  `--alert` pushes the durable record in the same pass.
- The legacy `stayawake-security-*` console scripts. `saw` is the only local security surface; the
  `stayawake-health-*` scripts are unchanged.

### Security
- A report written to disk stores a fingerprint rather than the raw payload; full evidence appears
  only on the live terminal.

## [0.1.4] - 2026-06-25

_No user-facing changes were recorded for this release. The unified `saw` CLI first shipped here and
is described under 0.1.5._

## [0.1.3] - 2026-06-25

### Changed
- Minimum Python lowered to 3.11.
- Health alerting keeps one self-updating issue per project: it names the failing dimension (status,
  latency, keyword or TLS), comments only on state transitions, and closes the issue on recovery
  after a configurable debounce.

### Fixed
- A completed scan no longer crashes when the reports directory is unwritable — for example a
  read-only or another user's bind-mount. The verdict is the exit code and report persistence is
  best-effort, so it warns and falls back to a temporary directory.

## [0.1.2] - 2026-06-25

_No user-facing changes were recorded for this release._

## [0.1.1] - 2026-06-25

### Added
- A container image on GHCR.
- The public GitHub Action moved to its own repository,
  [`Ndevu12/strix`](https://github.com/Ndevu12/strix).

### Changed
- Distribution renamed to `stayawakebot` on PyPI. The import package and console scripts are
  unchanged — only `pip install <name>` differs.
- Minimum Python lowered to 3.13.

## [0.1.0] - 2026-06-19

Initial public release: Health sentinel (uptime monitoring) and Security sentinel (supply-chain worm
detection, remediation, prevention) under one `stayawake` package.

[Unreleased]: https://github.com/Ndevu12/stayAwakeBot/compare/v0.7.0...HEAD
[0.7.0]: https://github.com/Ndevu12/stayAwakeBot/compare/v0.6.3...v0.7.0
[0.6.3]: https://github.com/Ndevu12/stayAwakeBot/compare/v0.6.2...v0.6.3
[0.6.2]: https://github.com/Ndevu12/stayAwakeBot/compare/v0.6.1...v0.6.2
[0.6.1]: https://github.com/Ndevu12/stayAwakeBot/compare/v0.6.0...v0.6.1
[0.6.0]: https://github.com/Ndevu12/stayAwakeBot/compare/v0.5.2...v0.6.0
[0.5.2]: https://github.com/Ndevu12/stayAwakeBot/compare/v0.5.1...v0.5.2
[0.5.1]: https://github.com/Ndevu12/stayAwakeBot/compare/v0.5.0...v0.5.1
[0.5.0]: https://github.com/Ndevu12/stayAwakeBot/compare/v0.4.1...v0.5.0
[0.4.1]: https://github.com/Ndevu12/stayAwakeBot/compare/v0.4.0...v0.4.1
[0.4.0]: https://github.com/Ndevu12/stayAwakeBot/compare/v0.3.1...v0.4.0
[0.3.1]: https://github.com/Ndevu12/stayAwakeBot/compare/v0.3.0...v0.3.1
[0.3.0]: https://github.com/Ndevu12/stayAwakeBot/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/Ndevu12/stayAwakeBot/compare/v0.1.19...v0.2.0
[0.1.19]: https://github.com/Ndevu12/stayAwakeBot/compare/v0.1.18...v0.1.19
[0.1.18]: https://github.com/Ndevu12/stayAwakeBot/compare/v0.1.17...v0.1.18
[0.1.17]: https://github.com/Ndevu12/stayAwakeBot/compare/v0.1.16...v0.1.17
[0.1.16]: https://github.com/Ndevu12/stayAwakeBot/compare/v0.1.15...v0.1.16
[0.1.15]: https://github.com/Ndevu12/stayAwakeBot/compare/v0.1.14...v0.1.15
[0.1.14]: https://github.com/Ndevu12/stayAwakeBot/compare/v0.1.13...v0.1.14
[0.1.13]: https://github.com/Ndevu12/stayAwakeBot/compare/v0.1.12...v0.1.13
[0.1.12]: https://github.com/Ndevu12/stayAwakeBot/compare/v0.1.11...v0.1.12
[0.1.11]: https://github.com/Ndevu12/stayAwakeBot/compare/v0.1.10...v0.1.11
[0.1.10]: https://github.com/Ndevu12/stayAwakeBot/compare/v0.1.9...v0.1.10
[0.1.9]: https://github.com/Ndevu12/stayAwakeBot/compare/v0.1.8...v0.1.9
[0.1.8]: https://github.com/Ndevu12/stayAwakeBot/compare/v0.1.7...v0.1.8
[0.1.7]: https://github.com/Ndevu12/stayAwakeBot/compare/v0.1.6...v0.1.7
[0.1.6]: https://github.com/Ndevu12/stayAwakeBot/compare/v0.1.5...v0.1.6
[0.1.5]: https://github.com/Ndevu12/stayAwakeBot/compare/v0.1.4...v0.1.5
[0.1.4]: https://github.com/Ndevu12/stayAwakeBot/compare/v0.1.3...v0.1.4
[0.1.3]: https://github.com/Ndevu12/stayAwakeBot/compare/v0.1.2...v0.1.3
[0.1.2]: https://github.com/Ndevu12/stayAwakeBot/compare/v0.1.1...v0.1.2
[0.1.1]: https://github.com/Ndevu12/stayAwakeBot/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/Ndevu12/stayAwakeBot/releases/tag/v0.1.0
