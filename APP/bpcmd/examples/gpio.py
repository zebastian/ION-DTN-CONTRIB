#!/usr/bin/env python3
import sys
import re
from pathlib import Path

GPIO = Path("/sys/class/gpio")

def export_pin(n):
    pin = GPIO / f"gpio{n}"
    if not pin.exists():
        (GPIO / "export").write_text(str(n))
    (pin / "direction").write_text("out")

def set_pin(n, value):
    export_pin(n)
    (GPIO / f"gpio{n}" / "value").write_text(str(value))

def get_pin(n):
    export_pin(n)
    return (GPIO / f"gpio{n}" / "value").read_text().strip()

def info():
    for chip in sorted(GPIO.glob("gpiochip*")):
        base = int((chip / "base").read_text())
        ngpio = int((chip / "ngpio").read_text())
        for n in range(base, base + ngpio):
            try:
                export_pin(n)
                val = (GPIO / f"gpio{n}" / "value").read_text().strip()
                direction = (GPIO / f"gpio{n}" / "direction").read_text().strip()
                print(f"gpio{n:<4} {direction} {val}")
            except OSError:
                pass

def usage():
    print(f"""Usage: {sys.argv[0]} <command>
Commands:
    set <N> <0|1>  Set gpio N low/high
    get <N>        Read gpio N value
    info           Export and show all available gpios
    help           Show this message""")

def main():
    cmd = sys.argv[1] if len(sys.argv) > 1 else "help"
    if cmd == "info":
        info()
    elif cmd in ("help", "-h", "--help"):
        usage()
    elif cmd in ("set", "get"):
        if len(sys.argv) < 3:
            print(f"{cmd} requires a pin number", file=sys.stderr)
            sys.exit(1)
        pin = int(sys.argv[2])
        if cmd == "set":
            if len(sys.argv) < 4 or sys.argv[3] not in ("0", "1"):
                print("set requires a value: 0 or 1", file=sys.stderr)
                sys.exit(1)
            set_pin(pin, int(sys.argv[3]))
        print(str(pin) + "=" + get_pin(pin))
    else:
        print(f"unknown command: {cmd}", file=sys.stderr)
        usage()
        sys.exit(1)

if __name__ == "__main__":
    main()