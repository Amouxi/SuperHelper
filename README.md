**Quick Disclaimer**
Special thanks to the contributors at https://gtfobins.github.io/ for their outstanding work. Their comprehensive database has been a lifesaver. This script utilizes their remarkable data to assist in identifying and analyzing potential security misconfigurations. Kudos to the GTFOBins team!

# Why SuperHelper
With SudoSuidFinder, you won't miss a thing! The script provides a clear and
color-coded output, making it easy to identify important information. It checks
available SUDO commands and available SUID binaries against https://gtfobins.github.io/, ensuring comprehensive coverage.

Looking at the output of tools like Linpeas, especially in the SUID section, can be tedious to read.
Linpeas doesn't differentiate between default binaries with SUID or custom binaries. This oversight can lead to missing critical SUID configurations and wasting time on rabbit holes.

# Features
* Standalone and Portable: This script is designed for portability and can be used offline, although it needs to be run online at least once for initial setup.
* Misconfiguration Detection: Searches for misconfigurations on SUID binaries and SUDO commands.
* Tested on Python 3.11: Compatibility has been verified with Python 3.11.

# Functionality
* Download and JSONify Data: Fetches and processes data available on https://gtfobins.github.io/. The JSON file can be stored locally or saved into local variable.
* List Possible SUID Binaries: Identifies potential SUID binaries with entries on GTFOBin, helping to pinpoint exploitable configurations.
* List Custom SUID Binaries: Highlights custom SUID binaries that may have unique configurations on the system.
* List Available SUDO Commands: Displays a comprehensive list of available SUDO commands, cross-referenced with GTFOBin entries.

# Usage Notes
* Initial Setup: The script needs to run online at least once to parse GTFOBins site and create a JSON file used for subsequent offline runs.
Execute `python SuperHelper.py -d` to parse GTFOBin database into json format and save it into file.
```commandline
python main.py -d
```
* Local Variable: Parsed GTFOBin data as base64-encoded variable within the script. This allows offline usage without the need for online retrieval mini.
Execute `python SuperHelper.py -cb` to obtain base64 encoded version of the json data.
```commandline
python main.py -cb
eyc3ei[...SNIPPED...]LCAnc3VkbyddfQ==
```
Copy the data and replace the variable `BASE64_ENCODED_GTFOBIN` variable which currently is set to `CHANGETHIS` in its place.
Now execute `python SuperHelper.py -lb` to use the base64 encoded json data.
```commandline
python main.py -s -S -p kali -lb
```

# Help message
```commandline
usage: main.py [-h] [-s | --suid | --no-suid] [-S | --sudo | --no-sudo] [-p PASSWD] [-lb | --lbase64 | --no-lbase64] [-cb | --cbase64 | --no-cbase64] [-d | --download | --no-download]

Perform checks for SUDO/SUID

options:
  -h, --help            show this help message and exit
  -s, --suid, --no-suid
                        Check for SUID binaries.
  -S, --sudo, --no-sudo
                        Check for SUDO permissions.
  -p PASSWD, --passwd PASSWD
                        Specify the password used to check SUDO (default is "")
  -lb, --lbase64, --no-lbase64
                        Load GTFOBin data from local base64-encoded variable: (BASE64_ENCODED_GTFOBIN).
  -cb, --cbase64, --no-cbase64
                        Create base64-encoded GTFOBin data. (Action requires an internet connection.)
  -d, --download, --no-download
                        Download GTFOBins data. (Action requires an internet connection.)
```
# Download and parse GTFOBins data
```commandline
python main.py -d
```

# Create base64-encoded GTFOBin data (Action requires an internet connection)
```commandline
python main.py -cb
eyc3ei[...SNIPPED...]LCAnc3VkbyddfQ==
```

# Check SUDO commands using a local base64-encoded variable
```commandline
python main.py -S -p Password123! -lb
```
# Check for SUID binaries
```commandline
python main.py -s
```

# Check both SUDO commands and SUID binaries together
```commandline
python main.py -s -S -p Password123! 
```

# Print example:
![output-example](https://github.com/Amouxi/SuperHelper/assets/48153396/5d6c760d-10f8-425c-9f32-054779a1d620)
# Disclaimer:
```
This script is provided for educational purposes only. The author is not responsible
for any misuse or damage caused by the use of this script. Use it responsibly and
only on systems you have explicit permission to analyze.
```



