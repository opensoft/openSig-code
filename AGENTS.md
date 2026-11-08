This is the **code leg** of openSig (`opensig`): the implementation
and its tests.

**The project's rules are not here.** They are in the assembly root
`opensoft/openSig`, in `AGENTS-shape.md` — read that before touching anything
that spans the legs. This leg is mounted there at `code/`, and the other leg,
`opensoft/openSig-spec`, beside it at `../spec/`, once the root is cloned with
`--recurse-submodules`.

Working here is ordinary — an ordinary repository on an ordinary branch. What
advancing this leg does NOT do is advance the project: that is ONE commit in
`opensoft/openSig` moving the gitlink, `contracts/code-pin.yaml` and every
workflow `@<sha>` for this leg together.

Being the code leg confers no authority over the implementation. The split is
navigation.
