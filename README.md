# ION-DTN-CONTRIB

Community contributions for [ION-DTN](https://github.com/nasa-jpl/ION-DTN), NASA/JPL's
implementation of Delay/Disruption Tolerant Networking (DTN).

This repository collects contributions extending ION-DTN: 
- Convergence Layer Adapter (CLA)
- Link Service Adapter (LSA)
- applications interacting with ION-DTN / sending over it
- other software

## Information about the Software 
- The software in this repository is licensed under MIT.
- Each sub-project is written and maintained by the author of that project.

## Building

Contributions are built against an **installed** ION-DTN.

On Debian/Ubuntu, install the build prerequisites first with `install-deps.sh`.
It installs the general toolchain and, optionally, each selected CLA's own
dependencies:

```bash
./install-deps.sh            # general build deps only
./install-deps.sh ALL        # general deps + every CLA
./install-deps.sh CLA_MQTT   # general deps + the named CLA(s)
```

Then build:

```bash
autoreconf -fi
./configure
make
sudo make install
```

`configure` locates the installed ION headers and libraries (default prefix
`/usr/local`) and checks each contribution's own dependencies. Per-contribution
build notes and dependencies live in each sub-project's `README.md`.

## Testing

`test.sh` exercises each selected contribution's `tests/` folder:

```bash
./test.sh                run every CLA's tests
./test.sh ALL            run every CLA's tests
./test.sh CLA_MQTT       run only the named CLA(s)
```

Each test directory's `dotest` is run (exit 0 = pass) followed by its
`cleanup`. Tests marked `.optional` (e.g. ones needing an external broker) are
reported but never fail the run; any other failure makes `test.sh` exit
non-zero.