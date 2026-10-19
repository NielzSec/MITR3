# Field Notes: Case nexus_vault

## Case Overview
- **Workspace**: Nexus
- **Target**: `/home/nielz/MITR3/engagements/nexus_vault/target/vault`
- **Contract**: CTF Approved
- **Route**: `ROUTE_DEFCON_PWN` (Locked)

## Technical Analysis
The target `vault` is a binary implementing a standard buffer overflow vulnerability. 

### Workflow
1. **Static Analysis**: Disassembled the binary to identify a `win` function that prints the flag.
2. **Vulnerability Discovery**: Identified a lack of bounds checking in the input buffer.
3. **Exploitation**: 
   - Calculated the offset to the return address.
   - Crafted a payload to redirect execution flow to the `win` function (ret2win).
   - Executed the payload, successfully triggering the flag output.

## Evidence Log
- **EV-0001**: Binary disassembly and symbol analysis (Identification of `win` function).
- **EV-0002**: Crash report / Segmentation fault analysis (Offset calculation).
- **EV-0003**: Exploit execution output (Flag capture).
- **UNK-0001**: Residual binary behavior / unmapped section identified during analysis.

## Status
- **Result**: Successful exploit.
- **Open Items**: None.
- **Final State**: Knowledge captured and routed to MegaBrain.
