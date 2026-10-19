# STRIDE

| Letter | Threat | Question to ask |
|---|---|---|
| S | Spoofing | Can someone pretend to be another user or service? |
| T | Tampering | Can data in transit or at rest be modified undetected? |
| R | Repudiation | Can an action be denied later because it was not logged? |
| I | Information disclosure | Can data be read by someone not entitled to it? |
| D | Denial of service | Can one actor exhaust a shared resource? |
| E | Elevation of privilege | Can a low-privilege actor gain more rights? |

## How to apply it

1. Draw the data-flow diagram: actors, processes, data stores, flows.
2. Mark trust boundaries where data crosses privilege levels.
3. Apply STRIDE to each element and each flow crossing a boundary.
4. Record the threat, the mitigation and who owns it.
5. Revisit when the architecture changes — a threat model is a living document.
