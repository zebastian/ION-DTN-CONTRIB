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

Contributions are built against an **installed** ION-DTN:

```bash
autoreconf -fi
./configure
make
sudo make install
```

`configure` locates the installed ION headers and libraries (default prefix
`/usr/local`) and checks each contribution's own dependencies. Per-contribution
build notes and dependencies live in each sub-project's `README.md`.