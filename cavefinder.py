import argparse

__version__ = "1.0.0"

WELCOME = """
                      /=============\\
                     /      | |      \\  
   ______                   | |     ______ _             __           
  / ____/____ _ _   __ ___  | |    / ____/(_)____   ____/ /___   _____
 / /    / __ `/| | / // _ \ | |   / /_   / // __ \ / __  // _ \ / ___/
/ /___ / /_/ / | |/ //  __/ | |  / __/  / // / / // /_/ //  __// /    
\____/ \__,_/  |___/ \___/  |_| /_/    /_//_/ /_/ \__,_/ \___//_/ v:%s"""


def main():
    parser = argparse.ArgumentParser(description="Dig in a binary to find all code caves")
    parser.add_argument("binary", help="Executable file")
    parser.add_argument("--size", help="Minimum size of a code cave, Default: 100", type=int, default=100)
    parser.add_argument("--bytes", help="Bytes to search, Default: 0x00", type=str, default="\x00")
    args = parser.parse_args()


if __name__ == "__main__":
    print(WELCOME % __version__, end='\n\n')
    main()
