import yaml
import os
import re
from burp import IBurpExtender, ITab
from javax.swing import JPanel, JButton, JFileChooser, JLabel, BoxLayout, JTextArea, JScrollPane, JSplitPane, JTabbedPane, JTextField, SwingUtilities, UIManager, BorderFactory, JTable, ListSelectionModel
from java.awt import Dimension, FlowLayout, GridBagConstraints, GridBagLayout, BorderLayout, Font, Insets
from javax.swing.table import DefaultTableModel
from javax.swing.event import ListSelectionListener, DocumentListener
import json

class BurpExtender(IBurpExtender, ITab):
    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        self.request_counter = 1  # Initialize the counter
        callbacks.setExtensionName("OpenAPI YAML Parser (3.0)")

        # Main Panel with BorderLayout
        self._panel = JPanel()
        self._panel.setLayout(BorderLayout())

        # Create the North panel with input fields and buttons
        north_panel = self.create_north_panel()
        self._panel.add(north_panel, BorderLayout.NORTH)

        # Create the central split pane with the request viewer and the table
        split_pane = self.create_split_pane()
        self._panel.add(split_pane, BorderLayout.CENTER)

        # Create a status label at the bottom
        self._status_label = JLabel("")
        self._panel.add(self._status_label, BorderLayout.SOUTH)

        # Add the custom tab to Burp
        callbacks.addSuiteTab(self)

    def getTabCaption(self):
        return "OpenAPI Importer"

    def getUiComponent(self):
        return self._panel

    def create_north_panel(self):
        resource_panel = JPanel(GridBagLayout())
        resource_panel.setBorder(BorderFactory.createMatteBorder(0, 0, 1, 0, UIManager.getLookAndFeelDefaults().getColor("Separator.foreground")))

        self.resourceTextField = JTextField(30)
        self.loadButton = self.create_button("Load", self.load_yaml)
        self.loadButton.setEnabled(False)

        browseButton = self.create_button("Browse", self.browse_for_file)

        gbc = GridBagConstraints()
        gbc.insets = Insets(0, 5, 0, 5)

        resource_panel.add(JLabel("Parse from local file:"), gbc)

        gbc.fill = GridBagConstraints.HORIZONTAL
        gbc.gridx = 1
        gbc.weightx = 1
        gbc.insets = Insets(0, 0, 0, 0)
        resource_panel.add(self.resourceTextField, gbc)

        gbc.gridx = 2
        gbc.weightx = 0
        gbc.insets = Insets(0, 0, 0, 5)
        east_panel = JPanel(FlowLayout(FlowLayout.RIGHT))
        east_panel.add(browseButton)
        east_panel.add(self.loadButton)
        resource_panel.add(east_panel, gbc)

        # Document listener to enable the load button when the text field is not empty
        self.resourceTextField.getDocument().addDocumentListener(DocumentListenerAdapter(self.loadButton, self.resourceTextField))

        return resource_panel

    def create_split_pane(self):
        # Create a table model with columns: ID, Host, Method, URL, Parameters, Description, Entry (hidden)
        self.table_model = DefaultTableModel(["ID", "Host", "Method", "URL", "Parameters", "Description", "Entry"], 0)
        self.request_table = JTable(self.table_model)
        self.request_table.setSelectionMode(ListSelectionModel.SINGLE_SELECTION)

        # Hide the "Entry" column (last column)
        self.request_table.getColumn("Entry").setMinWidth(0)
        self.request_table.getColumn("Entry").setMaxWidth(0)
        self.request_table.getColumn("Entry").setWidth(0)

        # Add a listener to display request details when a row is selected
        self.request_table.getSelectionModel().addListSelectionListener(ListSelectionListenerAdapter(self))

        scroll_pane_table = JScrollPane(self.request_table)

        # Create a text area to show the selected request details
        self._text_area = JTextArea()
        self._text_area.setEditable(False)
        scroll_pane_details = JScrollPane(self._text_area)

        # Create split pane
        split_pane = JSplitPane(JSplitPane.VERTICAL_SPLIT)
        split_pane.setTopComponent(scroll_pane_table)
        split_pane.setBottomComponent(scroll_pane_details)
        split_pane.setResizeWeight(0.6)

        return split_pane

    def build_params_list(self, entry):
        # Start with an empty list of parameters
        param_list = []

        # Extract parameters from the request body (if any)
        request_body = entry.get('request')
        if request_body:
            # Attempt to extract JSON body parameters
            try:
                body_params = json.loads(request_body.split("\r\n\r\n", 1)[1])
                param_list += [key for key in body_params.keys()]
            except (ValueError, IndexError):
                pass  # Handle non-JSON or empty bodies gracefully

        # Extract parameters from the URL (if any)
        url = entry.get('url', '')
        if '?' in url:
            query_string = url.split('?', 1)[1]
            url_params = query_string.split('&')
            param_list += ["{}".format(param.split('=')[0]) for param in url_params]

        # Return the parameter list or "No parameters" if the list is empty
        return "; ".join(param_list) if param_list else "No parameters"

    def create_button(self, text, action):
        button = JButton(text)
        button.setBackground(UIManager.getColor("Burp.burpOrange"))
        button.setFont(Font(button.getFont().getName(), Font.BOLD, button.getFont().getSize()))
        button.setForeground(UIManager.getColor("Burp.primaryButtonForeground"))
        button.addActionListener(action)
        return button

    def browse_for_file(self, event):
        chooser = JFileChooser()
        ret = chooser.showOpenDialog(self._panel)
        if ret == JFileChooser.APPROVE_OPTION:
            file = chooser.getSelectedFile()
            self.resourceTextField.setText(file.getAbsolutePath())
            self.loadButton.setEnabled(True)
        else:
            self._status_label.setText("No file selected")

    def load_yaml(self, event):
        file_path = self.resourceTextField.getText()
        if file_path:
            self.process_yaml_file(file_path)

    def process_yaml_file(self, file_path):
        # Load the YAML file
        with open(file_path, 'r') as yaml_file:
            openapi_spec = yaml.safe_load(yaml_file)

        # Reset counter
        self.request_counter = 1

        # Clear the table and text area before loading new content
        self.table_model.setRowCount(0)
        self._text_area.setText("")

        # Parse the OpenAPI specification and create requests
        log_entries = self.parse_openapi(openapi_spec)

        # Add each entry to the table
        for entry in log_entries:
            request = entry['request']
            host = entry['host']
            method = entry['method']
            url = entry['url']
            description = entry['description'] if entry['description'] else "No description available"
            params = self.build_params_list(entry)  # Extract the parameters list

            # Add the data to the table, storing the entire entry in the last column
            self.table_model.addRow([self.request_counter, host, method, url, params, description, entry])

            # Increment the request counter
            self.request_counter += 1

            # Create the HttpService
            http_service = self._helpers.buildHttpService(host, entry['port'], entry['protocol'] == "https")

            # Send the request to the Repeater tab
            self._callbacks.sendToRepeater(http_service.getHost(), http_service.getPort(), http_service.getProtocol() == "https", self._helpers.stringToBytes(request), str(self.request_counter))

        print("Requests imported to Repeater")



    def parse_openapi(self, openapi):
        log_entries = []

        for server in openapi.get('servers', []):
            server_url = server.get('url', 'https://example.com')
            for path, path_item in openapi.get('paths', {}).items():
                operation_map = self.get_operation_map(path_item)
                for method, operation in operation_map.items():
                    if operation:
                        entry = self.build_request(server_url, path, method, operation, openapi.get('components', {}).get('schemas', {}))
                        log_entries.append(entry)

        return log_entries

    def get_operation_map(self, path_item):
        return {
            'DELETE': path_item.get('delete'),
            'GET': path_item.get('get'),
            'HEAD': path_item.get('head'),
            'PATCH': path_item.get('patch'),
            'POST': path_item.get('post'),
            'PUT': path_item.get('put'),
            'TRACE': path_item.get('trace')
        }

    def build_request(self, server_url, path, method, operation, schemas):
        entry = {}
        try:
            # Use the original placeholder format
            path_with_placeholders = path  # Keep the original {param} format

            # Manually extract host and port from server_url
            if server_url.startswith("http://"):
                protocol = "http"
                port = 80
                host = server_url[len("http://"):].split("/")[0]
            elif server_url.startswith("https://"):
                protocol = "https"
                port = 443
                host = server_url[len("https://"):].split("/")[0]

            # Construct the query string for GET requests
            if method.upper() == "GET":
                query_string = self.build_query_string(operation.get('parameters'))
                if query_string:
                    path_with_placeholders += '?' + query_string

            # Create the request line with HTTP/1.1
            request_line = "{} {} HTTP/1.1".format(method.upper(), path_with_placeholders)
            # Build headers, including the Host header
            headers = self.build_http_headers(host, method, path_with_placeholders, operation.get('requestBody'), operation.get('responses'))

            # Construct the request body (parameters)
            request_body = self.build_http_body(operation.get('parameters'), operation.get('requestBody'), schemas)

            # Combine request line, headers, and body into a full HTTP request
            header_lines = "\r\n".join(["{}: {}".format(header['name'], header['value']) for header in headers])
            request = "{}\r\n{}\r\n\r\n{}".format(request_line, header_lines, request_body)

            # Store request details for the table
            entry = {
                'request': request,
                'host': host,
                'method': method.upper(),
                'url': path_with_placeholders,
                'port': port,
                'protocol': protocol,
                'description': operation.get('description', '')
            }

        except Exception as e:
            self._status_label.setText("Error creating request: " + str(e))

        return entry

    def build_query_string(self, parameters):
        query_params = []
        if parameters:
            for param in parameters:
                if param['in'] == 'query':
                    name = param['name']
                    example = param.get('example', param.get('schema', {}).get('type', ''))
                    query_params.append("{}={}".format(name, example))
        return "&".join(query_params)

    def build_http_headers(self, host, method, path, request_body, api_responses):
        headers = []

        # Include the Host header
        headers.append({'name': 'Host', 'value': host})

        # Handle content-type
        if request_body and request_body.get('content'):
            content_type = list(request_body['content'].keys())[0]
            headers.append({'name': 'content-type', 'value': content_type})

        # Handle accept header
        if api_responses:
            response_200 = api_responses.get('200')
            if response_200 and response_200.get('content'):
                accept_header_value = ",".join(response_200.get('content').keys())
                headers.append({'name': 'Accept', 'value': accept_header_value})

        return headers
    
    def build_http_body(self, parameters, request_body, schemas):
        body_params = {}

        if request_body and request_body.get('content'):
            # Get the content type
            content_type = list(request_body['content'].keys())[0]
            
            media_type = request_body['content'][content_type]
            schema_ref = media_type.get('schema', {}).get('$ref')
            if schema_ref:
                schema_name = schema_ref.split('/')[-1]
                schema_properties = schemas.get(schema_name, {}).get('properties', {})
                for name, prop in schema_properties.items():
                    example = prop.get('example')
                    value = example if example else prop.get('type', '')
                    body_params[name] = value

            # Conditional based on content-type
            if content_type == 'application/json':
                # Return as JSON formatted string
                return json.dumps(body_params)
            elif content_type == 'application/x-www-form-urlencoded':
                # Return as URL-encoded string
                return "&".join(["{}={}".format(name, value) for name, value in body_params.items()])
            elif content_type == 'multipart/form-data':
                # Return as multipart/form-data
                return body_params
            elif content_type == 'text/plain':
                # Return as plain text
                return "\n".join(["{}: {}".format(name, value) for name, value in body_params.items()])
            elif content_type == 'application/xml':
                # Return as XML
                return "<root>" + "".join(["<{}>{}</{}>".format(name, value, name) for name, value in body_params.items()]) + "</root>"
        
        # Return empty string if no body is needed or recognized content-type
        return ""
    
    def build_http_parameters(self, parameters, request_body, schemas):
        params = []

        if parameters:
            for param in parameters:
                param_in = param.get('in')
                param_name = param.get('name')
                schema = param.get('schema', {})
                param_value = schema.get('type', '')

                if param_in == 'header':
                    params.append({'name': param_name, 'value': param_value})
                elif param_in == 'query':
                    params.append({'name': param_name, 'value': param_value})

        if request_body and request_body.get('content'):
            media_type = list(request_body['content'].values())[0]
            schema_ref = media_type.get('schema', {}).get('$ref')
            if schema_ref:
                schema_name = schema_ref.split('/')[-1]
                schema_properties = schemas.get(schema_name, {}).get('properties', {})
                for name, prop in schema_properties.items():
                    example = prop.get('example')
                    value = example if example else prop.get('type', '')
                    params.append({'name': name, 'value': value})

        return params

class DocumentListenerAdapter(DocumentListener):
    def __init__(self, button, textField):
        self.button = button
        self.textField = textField

    def insertUpdate(self, e):
        self.updateLoadButton()

    def removeUpdate(self, e):
        self.updateLoadButton()

    def changedUpdate(self, e):
        self.updateLoadButton()

    def updateLoadButton(self):
        SwingUtilities.invokeLater(lambda: self.button.setEnabled(bool(self.textField.getText().strip())))

class ListSelectionListenerAdapter(ListSelectionListener):
    def __init__(self, extender):
        self.extender = extender

    def valueChanged(self, event):
        selected_row = self.extender.request_table.getSelectedRow()
        if selected_row >= 0:
            # Access the full entry stored in the last column of the table
            entry = self.extender.table_model.getValueAt(selected_row, 6)  # Adjusted index due to added Parameters column
            if entry:
                method = entry['method']
                url = entry['url']
                host = entry['host']
                description = entry['description'] if entry['description'] else "No description available"

                # Use the build_params_list method from BurpExtender
                params = self.extender.build_params_list(entry)

                # Format the request details using .format()
                request_details = (
                    "Request {}\n\n"
                    "Method: {}\n"
                    "URL: {}\n"
                    "Host: {}\n"
                    "Params: {}\n\n"
                    "Description: {}"
                ).format(selected_row + 1, method, url, host, params, description)

                # Display the formatted request details in the text area
                self.extender._text_area.setText(request_details)










