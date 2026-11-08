# openSig-code

The **code leg** of the `opensig` project: the implementation and its
tests. The requirements it implements live in
[`opensoft/openSig-spec`](https://github.com/opensoft/openSig-spec).

**Clone the assembly root, not this repository.** This leg is mounted as a
submodule at `code/` inside
[`opensoft/openSig`](https://github.com/opensoft/openSig), which
is what pins the commit of this repository that the project currently is:

```sh
git clone --recurse-submodules https://github.com/opensoft/openSig.git
cd openSig
make bootstrap
```

Working here directly is fine — it is an ordinary repository with an ordinary
branch. What advancing this leg does NOT do is advance the project: that is a
commit in the assembly root moving the gitlink, `contracts/code-pin.yaml` and
any workflow `@<sha>` reference together.

Being the code leg confers no authority over the implementation. The split is
navigation; authority travels in grants, and a project that keeps spec and
code in one repository is reviewed identically.

Topic: `xf-project-opensig`.

## Intended components

- **openSig**: envelope workflow, API, permissions and evidence.
- **openAutograph**: review, consent, authenticated human approval and visible signatures.
- **openCryptograph**: certificate-backed signatures, organizational seals, timestamps and verification.
- Consumer adapters for Hermes, openChart and openPractice; optional ledger adapters.

All original implementation will use Apache-2.0, with MIT/Apache-only shipped third-party materials. This repository currently contains a scaffold, not a signing runtime. Canonical architecture, OpenSpec changes and Speckit feature plans belong in the spec leg; do not duplicate their task lists here. See the [implementation plan](https://github.com/opensoft/openSig-spec/blob/docs/opensig-foundation/ideation/brainstorm/opensig-implementation-plan.md).
