# Working on sequentia-contracts

Notes for AI coding agents and new contributors. `README.md` says what this
repository is and how to use it; this file covers the conventions that are not
obvious from the code. Node and consensus conventions live in the
[`Sequentia`](https://github.com/ConcatenaLabs/Sequentia) repository, whose
`CLAUDE.md` and `doc/sequentia/` are authoritative for the chain itself.

## Things that are expensive to get wrong

- **The compiler is pinned exactly, and only here.** A commitment Merkle root
  depends on the compiler version, so a version bump can move every address.
  Change `simplicityhl` only in `crates/sequentia-contracts/Cargo.toml` (with
  `=`), update `COMPILER_VERSION` in `src/lib.rs`, run the parity gate, and
  recompile every program to compare its root before merging.
- **The parity gate guards consensus behaviour.** Never add an allow-list entry
  for a difference in a jet, a cost, the decoder, type inference or the budget
  check. The Rust jet table (names, costs, roots) has no allow-list at all. Such a difference means programs built here can be refused on the chain.
  An entry carries both content hashes; update them only after reading the diff.
- **The lints are not optional.** Do not add a program that uses `lbtc_asset` or
  a relative-timelock jet under any spelling. The only programs that do are the
  reject fixtures in `lints/fixtures/reject/`, which exist to prove the lints and
  the on-chain bypass. For a relative lock, use the pattern in
  `lints/fixtures/accept/safe_distance.simf`. A program passes only when it
  compiles, so that the compiled layer runs: `--source-only` is for helpers and
  templates alone, and a program with imports is linted as Simplex builds it
  (`seqc lint --project` or `--dep`).
- **A negative test proves nothing until it is refused in a block.** The node's
  mempool runs Simplicity as policy on every chain, even where consensus has not
  activated it, so a mempool rejection can hide a consensus flaw. Force every
  negative case into a block with the hidden `generateblock` RPC and record that
  error. In the harness, `reject()` does both and fails if the block accepts.
- **Simplicity must be active from genesis on a test chain.** A custom chain has
  it off unless the node starts with `-evbparams=simplicity:-1:::`. The form
  `simplicity:0:::` only activates at height 384, and until then a `0xbe` output
  is spendable by anyone.
- **Asset ids inside a program are in internal byte order**, the reverse of the
  hex the RPC prints.

- **A template is immutable once published.** Its hash is its identity, and
  addresses derived from it are in use. Change a program or a template only as a
  new template (a new directory, or a new `version`), then `seqc descriptor seal`
  it and regenerate its vectors. Never edit a vector by hand: regenerate it with
  `seqc descriptor vectors` and check that the mirrors still agree.
- **Helpers are part of every program that includes them.** Changing a helper
  changes the commitment root of every program that includes it. Add a new
  function rather than change one a published template uses, rerun `h1`, and
  update `docs/helpers.md` with what it measures.
- **The mirrors must stay compiler-free.** Python, JavaScript and Go derive an
  address with the standard library only, so any service can recognise a
  contract. Do not add a dependency to them.

## Working in this repository

- `cargo test` is the gate before every pull request; the parity gate needs a
  node checkout (`python3 parity/parity_gate.py --node <Sequentia>/src/simplicity`).
- The regtest harness needs a built node, so CI does not run it. Run
  `harness/run.py` before merging anything that touches a program, the harness or
  `seqc`, and commit the records it writes together with the regenerated
  `docs/harness-sizes.md` (`harness/compare.py`).
- Each harness test starts and stops its own node. Never leave a `sequentiad`
  running; `harness/tmp/` holds data directories only of failed tests.
- Pull requests go against `main`.

<!-- BEGIN SHARED AGENT CONVENTIONS: identical in every Sequentia repo. Change it in all of them together. -->
## Working with git and GitHub here

These rules are the same in every Sequentia repository. They are repeated in each
one because this file is the only thing an agent is guaranteed to read, whatever
machine it is working from.

**Nothing pushed to GitHub credits Claude, Anthropic, or any AI tool.** No
`Co-Authored-By: Claude` trailer, no `Claude-Session:` trailer or `claude.ai`
link, no "Generated with Claude Code" in a commit message or a pull request body,
no `claude/*` branch names or session ids, and no mention in source, comments,
docs or issue text. Agent tooling offers several of these by default; compose the
message without them rather than stripping them afterwards.

**Author every commit as the person the session is working for.** Several people
commit in these repositories and an agent always runs on behalf of one of them,
so derive the author from the authenticated GitHub account rather than from a
list of names that goes stale the moment somebody new arrives:

    git -c user.name="$(gh api user --jq '.name // .login')" \
        -c user.email="$(gh api user --jq '"\(.id)+\(.login)@users.noreply.github.com"')" \
        commit ...

That address is the GitHub `noreply` form, which is what links a commit to its
account and keeps private addresses out of a public history. When `gh` is not
authenticated as the person the work belongs to, ask them instead of guessing.

**Never infer the author from `git log`.** The clones carry no `user.name` or
`user.email`, so `git commit` stops with "Author identity unknown" and the
nearest answer to hand is the author of the last commit — which is whoever
pushed last and says nothing about who is working now. Attributing a commit to
someone who did not write it puts their name on code they never reviewed, and
taking it back costs a history rewrite and a force-push over commits other
machines have already pulled.

**Every change lands through a pull request that you merge yourself, at once.**
There is no reviewer on this project; the pull request exists so the reasoning is
recorded beside the diff. Branch, push, open it, merge it, delete the branch, all
in one sitting. Pushing straight to the default branch is the rule most often
broken here, and it is the one that costs the record. A pull request stays open
only when the repository owner asks for that specific one, and that never carries
over to the next.

**Name branches `area/short-description`**: `fix/`, `doc/`, `feature/`, `test/`,
`build/`, or the component being changed. Never a tool name, a session id, or
`worktree-*`.

**Write the subject as `area: what changed`**, one line, 72 characters at the
outside and 50 where you can manage it. Put the reasoning in the body, and
explain why rather than what.

**These repositories are public and world-readable.** Never commit private keys,
seeds, `wallet.dat`, RPC credentials, `.env` files or API tokens. Read the diff
before every commit. Secrets belong on the server and in offline backups.

**A file belongs to the repository whose code it describes.** Decide which repo
owns it before writing it; if it landed in the wrong one, move it rather than
deleting it.

**Documentation is part of the change, not a follow-up.** A change that makes a
README, a doc page, a runbook or a code comment wrong is not finished until that
text is right again, in the same pull request as the code. Before you open the
pull request, search the repository for whatever you renamed, moved or removed —
the old binary name, the old path, the old flag, the old command — and fix every
hit. If the change falsifies another repository's documentation, that repository
gets its own pull request in the same sitting. A stale instruction costs a new
user more than a missing one: they trust it, run it, it fails, and the failure
reads as broken software rather than as an out-of-date sentence.

**Write documentation to be timeless.** Assume the reader is new, arrived today,
and wants to know what the software is and how to use it right now. They do not
care what changed, what it used to be called, or which version added what. So
write in the present tense about current behaviour, and leave the history out:
no changelogs, no "new in", no "recently", no "coming soon", no status or
progress sections, no roadmaps, no dated notes. Quote a version number only where
the reader cannot act without it, and prefer pointing at the file that carries it
over copying the digits. Timeless does not mean thin — what the product is, who
it is for, and how to install, configure and use it all still belong there, in
full. Documentation written this way survives a release without an edit, which is
what keeps it true; the history already has homes in the git log, the tags and
the release notes.

**Push the same day you commit.** The testnet server pulls only from GitHub, so a
branch left on one laptop is invisible to every other machine and to the box.
<!-- END SHARED AGENT CONVENTIONS -->
