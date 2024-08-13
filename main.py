import yaml
import os
import re
from burp import IBurpExtender, ITab
from javax.swing import JPanel, JButton, JFileChooser, JLabel, BoxLayout, JTextArea, JScrollPane
from java.awt import Dimension, FlowLayout, GridBagConstraints, GridBagLayout, BorderLayout
from java.net import URI
from java.util import ArrayList
from burp import IHttpRequestResponse
import json

class BurpExtender(IBurpExtender, ITab):
    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        self.request_counter = 1  # Initialize the counter
        callbacks.setExtensionName("OpenAPI YAML Parser (3.0)")

        # Create the tab panel
        self._panel = JPanel()
        self._panel.setLayout(BoxLayout(self._panel, BoxLayout.Y_AXIS))

        buttons_panel = JPanel()
        buttons_panel.setLayout(FlowLayout(FlowLayout.CENTER))

        # Create the "Import YAML File" button
        self._button = JButton("Import YAML File", actionPerformed=self.import_yaml)
        buttons_panel.add(self._button)
        self._panel.add(buttons_panel, BorderLayout.NORTH)

        # Create a text area to show the loaded requests
        self._text_area = JTextArea()
        self._text_area.setEditable(False)
        scroll_pane = JScrollPane(self._text_area)
        scroll_pane.setPreferredSize(Dimension(500, 800))
        self._panel.add(scroll_pane, BorderLayout.CENTER)

        # Create a status label
        self._status_label = JLabel("")
        self._panel.add(self._status_label, BorderLayout.SOUTH)

        # Add the custom tab to Burp
        callbacks.addSuiteTab(self)

    def getTabCaption(self):
        return "OpenAPI Importer"

    def getUiComponent(self):
        return self._panel

    def import_yaml(self, event):
        # Open file chooser dialog
        self.request_counter = 1
        chooser = JFileChooser()
        ret = chooser.showOpenDialog(self._panel)
        if ret == JFileChooser.APPROVE_OPTION:
            file = chooser.getSelectedFile()
            self._status_label.setText("Loading: " + file.getAbsolutePath())
            self.process_yaml_file(file.getAbsolutePath())
        else:
            self._status_label.setText("No file selected")

    def process_yaml_file(self, file_path):
        # Load the YAML file
        with open(file_path, 'r') as yaml_file:
            openapi_spec = yaml.safe_load(yaml_file)

        # Clear the text area before loading new content
        self._text_area.setText("")

        # Parse the OpenAPI specification and create requests
        log_entries = self.parse_openapi(openapi_spec)

        separator_line = "-" * 50

        # Send requests to the Repeater and display them in the UI
        for entry in log_entries:
            request = entry['request']
            host = entry['host']
            port = entry['port']
            protocol = entry['protocol']
            description = "{}: {}".format(self.request_counter, entry['description'] if entry['description'] else "No description available")

            # Increment the request counter
            self.request_counter += 1

            # Create the HttpService
            http_service = self._helpers.buildHttpService(host, port, protocol == "https")

            # Send the request to the Repeater tab
            self._callbacks.sendToRepeater(http_service.getHost(), http_service.getPort(), http_service.getProtocol() == "https", self._helpers.stringToBytes(request), description)

            # Update the UI text area with the request and description
            self._text_area.append("{}\n".format(separator_line, description))
            self._text_area.append("Request {}:\n{}\nDescription: {}\n\n".format(self.request_counter - 1, request, description))

        self._status_label.setText("Requests imported to Repeater")

    def parse_openapi(self, openapi):
        log_entries = []

        for server in openapi.get('servers', []):
            server_url = server.get('url', 'https://example.com')
            for path, path_item in openapi.get('paths', {}).items():
                operation_map = self.get_operation_map(path_item)
                for method, operation in operation_map.items():
                    if operation:
                        self.build_request(log_entries, server_url, path, method, operation, openapi.get('components', {}).get('schemas', {}))

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

    def build_request(self, log_entries, server_url, path, method, operation, schemas):
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

            log_entries.append({
                'request': request,
                'host': host,
                'port': port,
                'protocol': protocol,
                'description': operation.get('description', '')
            })
        except Exception as e:
            self._status_label.setText("Error creating request: " + str(e))

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
