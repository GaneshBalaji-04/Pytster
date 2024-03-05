# Pytster

Pytster is an application designed to check whether a given hash, email address, IPv4 address, URL, or domain is malicious. Additionally, it provides detailed information about the input by consolidating data from various OSINT (Open Source Intelligence) websites. This tool simplifies the work of analysts by aggregating information in one place.

## Features

- Check the malicious status of hashes, email addresses, IPv4 addresses, URLs, and domains.
- Retrieve detailed information from various OSINT websites.
- User-friendly GUI implemented using the QT framework with C++.
- It provides information in json, pdf and text format.

## How it Works

Pytster utilizes API requests to interact with different OSINT websites, collecting valuable information. The tool is built in Python and appliaction of this tool is built in QT framework, leveraging the `requests` module for API interactions. The graphical user interface (GUI) is developed using the QT framework with C++ as the underlying programming language.

## Usage

1. **Installation:**
   - Clone the repository:
     ```bash
     git clone https://github.com/dharineeshj/Pytster.git
     ```
   - Navigate to the project directory.

2. **Dependencies:**
   - Ensure you have Python installed.
   - If you want to modify the look and beahviour of the application install Qt C++ framework and import the above C++ files in your Qt project.
   - Install required Python modules:
     ```bash
     pip install -r requirements.txt
     ```

3. **Run the Application:**
   - Execute the main script:
     ```bash
     python pytster-cmd.py
     ```

4. **Input and Analysis:**
   - Input the hash, email, IPv4 address, URL, or domain you want to analyze.
   - The application will perform checks and retrieve detailed information.

## Required Modules

- Python: `requests, fpdf, sys, json, base64, urllib.parse, os`

## Contributing

Contributions are welcome! If you'd like to contribute to Pytster, please follow these guidelines:
- Fork the repository.
- Create a new branch for your feature or bug fix.
- Make your changes and submit a pull request.

