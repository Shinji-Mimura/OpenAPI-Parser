## How to Install

### Prerequisites

This extension requires Jython standalone to run, as it uses Python 2.7 syntax compatible with Jython. You will also need to install some dependencies to ensure the extension works correctly.

### Installing Jython Standalone

1. **Download Jython Standalone**:
   - Download the Jython standalone JAR file from the [official website](https://www.jython.org/download).
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

2. **Verify Installation**:
   - After loading, you should see the extension listed in the `Extensions` tab with a green indicator if it loaded successfully.
   - You should also see a new tab named `OpenAPI Importer` in Burp Suite.

## How to Use

1. **Importing an OpenAPI YAML File**:
   - In the `OpenAPI Importer` tab, click on the `Import YAML File` button.
   - A file chooser dialog will appear. Select the OpenAPI YAML file you want to import.
   - The extension will parse the YAML file and generate HTTP requests based on the API definitions.

2. **Viewing and Managing Generated Requests**:
   - After importing the YAML file, the generated requests will appear in the text area below the button.
   - Each request is displayed with a separator line for clarity, including the full request details and a description.
   - If the description is missing from the YAML file, the extension will display "No description available."

3. **Sending Requests to the Repeater**:
   - All generated requests are automatically sent to the Repeater tab in Burp Suite.
   - The requests in the Repeater tab are numbered sequentially, starting from 1 each time a new YAML file is imported.
   - You can modify and send these requests from the Repeater tab as needed.

## License

This project is licensed under the MIT License. See the `LICENSE` file for more details.

