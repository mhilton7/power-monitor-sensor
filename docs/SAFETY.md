# Electrical safety

> **DANGER: mains voltage can kill, burn, arc, or start a fire. Firmware cannot make electrical work safe.**

This product only observes measurements. It does not disconnect a circuit, provide over-current protection, detect that conductors are de-energized, or establish a safe work condition. Never interpret a zero, missing, stale, or invalid reading as proof that a circuit is off.

Installation and service must be performed by a qualified person under the rules applicable to the site. De-energize, lock out where required, and independently verify absence of voltage with suitable equipment before opening an enclosure or moving a conductor. Follow the PZEM and CT manufacturers' ratings and instructions. Use appropriate enclosures, barriers, finger-safe terminals, fusing/protection, conductor sizes, insulation, strain relief, creepage/clearance, and environmental ratings.

The current transformer goes around exactly one current-carrying conductor. Clamping both line and neutral normally cancels the magnetic field and gives a misleading result. Never leave a current-output CT secondary open while current flows unless its manufacturer explicitly permits it. The PZEM voltage reference must be on the same monitored circuit and phase as the conductor in the CT.

Keep mains wiring and the PZEM mains side physically segregated from the ESP32, UART translator, USB, and microSD wiring. Do not route low-voltage leads through unprotected mains compartments. Protective earth is a safety conductor; it is not automatically the same node as low-voltage DC ground. Bonding and grounding decisions belong to the qualified system designer.

Software-only testing uses `SimulatedMeter` and the loopback server. Do not connect live mains equipment to run unit, frontend, protocol, simulator, or build tests.
