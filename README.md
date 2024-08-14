## About

This project is a Python adaptation of the popular [openapi-parser](https://github.com/aress31/openapi-parser) extension. The decision to rewrite this extension and use Python to adapt it had the following goals:

- To fix some of the extension's issues, primarily those related to the request body parser;
- To make it easier to incorporate modifications to the code as new OpenAPI specifications emerge.

## How to Install

### Prerequisites

This extension requires Jython standalone to run, as it uses Python 2.7 syntax compatible with Jython. You will also need to install `pyyaml` library to ensure the extension works correctly.

### Installing Jython Standalone

1. **Download Jython Standalone**:
   - Download the Jython standalone JAR file.
   - Ensure that you download version `2.7.3` as it is the latest stable release compatible with this extension.

2. **Install Required Dependencies**:
   - The extension relies on the `PyYAML` library to parse YAML files. Since Jython uses a different approach to install dependencies, follow these steps:

   ```bash
   java -jar jython-standalone-2.7.3.jar -m ensurepip
   java -jar jython-standalone-2.7.3.jar -m easy_install pyyaml==3.13
   ```

   - `ensurepip` will install `easy_install`, which is used to install `PyYAML` for Jython.
   - The command installs `PyYAML` version `3.13`, which is compatible with Python 2.7 and, by extension, Jython.

### Loading the Extension in Burp Suite

1. **Load the Extension**:
   - Open Burp Suite and navigate to the `Extender` tab.
   - Click on the `Extensions` sub-tab.
   - Click `Add` to load a new extension.
   - In the "Extension details" window:
     - Set "Extension type" to "Python".
     - For "Location", select the Jython standalone JAR (`jython-standalone-2.7.3.jar`) you downloaded.
     - For "Extension file", select the Python script for this extension.

## How to Use

   1. Click the "Browse" button to select your .yaml file.
   2. A file chooser dialog will appear. Select the OpenAPI YAML file you want to import.
   3. The extension will parse the YAML file and generate HTTP requests based on the API definitions.
   4. After importing the YAML file, the generated requests will be displayed in a table format.
      - If the description is missing from the YAML file, the extension will display "No description available."
   5. All generated requests are automatically sent to the Repeater tab in Burp Suite.
      - The requests in the Repeater tab are numbered sequentially, starting from 1 each time a new YAML file is imported.

## TODO List

### Features to Implement
- [ ] **Authentication Support:** Integrate authentication mechanisms, such as API keys, OAuth, or JWT tokens, into generated requests.

### UI Improvements
- [ ] **Enhanced Request Viewer:** Replace the current text area with a more interactive request editor or viewer component.
- [ ] **Filter and Search:** Implement filtering and search capabilities within the request table to quickly locate specific requests.
- [ ] **Sortable Columns:** Allow table columns to be sortable by clicking on headers (e.g., sorting requests by ID, Method, or URL).

## License

This project is licensed under the MIT License. See the `LICENSE` file for more details.

