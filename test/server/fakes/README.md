Stand-ins for the system tools `server/install-server.sh` drives, so
`test/server/install-flow.test.mjs` can run its real install, rotate,
doctor and uninstall flows against a scratch root (`$OPENROUTE_ROOT`)
without touching the machine.

Each one logs its arguments to `$FAKE_DIR/log` and keeps its state as
plain files in `$FAKE_DIR`; the tests set that state up and read it back.
sing-box, openssl (except `s_client`) and coreutils are the real ones.
