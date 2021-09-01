"""
# Copyright (c) 2021
# Author: Matt Smith <https://github.com/Mediab0t/>
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.
"""

import argparse
import configparser
import csv
import datetime
import io
import ipaddress
import logging
import logzero
from logzero import logger as log
import os
import prettytable
import requests
import re
import sys
import time
import urllib3
import xmltodict

''' Module Information '''
__author__ = "Matt Smith <https://github.com/Mediab0t/>"
__copyright__ = "Copyright 2021, Palo Alto Networks, Inc."
__license__ = "GPLv3"
__version__ = "0.0.0"
__status__ = "alpha"
__repository__ = "https://github.com/Mediab0t/cdss_api/"

''' Global Constants '''
separator = 128 * '-'
separator_half = separator[:len(separator) // 2]
date_format = "%Y-%m-%d %H:%M:%S"
timestamp = datetime.datetime.now().strftime(date_format)

''' Global Helper Functions '''


def exec_read_configuration(config_file):
    """
    Reads the contents of the configuration.ini and loads it into a dict

    Args:
        config_file (str): Path to the configuration.ini file

    Returns:
        config (dict): Configuration dict

    """
    try:

        # Message to let the user know we're doing something
        log.debug('Attempting to read and parse configuration from ' + config_file)

        # Check if our configuration file exists
        check = os.path.isfile(config_file)
        if check is False:

            # Check failed, raise exception
            raise Exception('Could not open configuration file: ' + config_file)

        else:

            # Check passed, let's try read it
            raw_config = configparser.ConfigParser()
            raw_config.read(config_file)

            # Attempt to map the configuration
            conf = {
                'autofocus': {
                    'host': raw_config.get('autofocus', 'af_host'),
                    'api_key': raw_config.get('autofocus', 'af_key'),
                },
                'wildfire': {
                    'host': raw_config.get('wildfire', 'wf_host'),
                    'api_key': raw_config.get('wildfire', 'wf_key'),
                },
                'general': {
                    'tls_verify': raw_config.getboolean('general', 'tls_verify'),
                    'timeout': raw_config.getint('general', 'timeout'),
                    'halt_on_error': raw_config.getboolean('general', 'halt_on_error')
                }
            }

            # Perform some assertion checks on wildfire-specifics
            assert isinstance(conf['wildfire']['host'], str), "Expecting string for 'wf_host'"
            assert isinstance(conf['wildfire']['api_key'], str), "Expecting string for 'wf_key'"

            # Perform some assertion checks on general
            assert isinstance(conf['general']['tls_verify'], bool), "Expecting bool for 'tls_verify'"
            assert isinstance(conf['general']['timeout'], int), "Expecting int for 'timeout'"
            assert isinstance(conf['general']['halt_on_error'], bool), "Expecting bool for 'halt_on_error'"

            # On our string inputs, check if they are empty
            assert conf['wildfire']['host'] != '', "Value for: 'wildfire host' cannot be empty"
            assert conf['wildfire']['api_key'] != '', "Value for: 'wf_key' cannot be empty"

            # Output contents of the config dict to the debug log
            log.debug('Constructed configuration dict: ' + str(conf))

            # Cleanup
            del check
            del raw_config

            # Return the config dict
            return conf

    except (AssertionError, Exception) as e:
        log.exception(e)
        if config.get('general', {}).get('halt_on_error', True) is True:
            sys.exit(1)
        else:
            pass


def exec_calc_exec_time(start_time, formatted_output=True):
    """
    Calculates the time delta between the supplied start argument and now
    Outputs a nicely formatted output rounded up to minutes if needed

    Args:
        start_time (float, int): Variable containing the start time data
        formatted_output (bool): Return a formatted string if true, raw value if false

    Returns:
        output (str): Formatted string containing calculated output if formatted_output is True
        output (float): Returns the raw calculated number if formatted_output is False

    """

    try:

        # Check if the input is a float or an int
        assert isinstance(start_time, (float, int)), "Expecting float or integer for parameter: start_time"

        # Assign the current time to now
        now = time.time()

        # Perform the time calculation, rounded to 2 decimal places
        end = round(now - start_time, 2)

        # Debug output
        log.debug('Current: ' + str(now) + ' / Start: ' + str(start_time) + ' / Delta: ' + str(end))

        # Check if we are outputting a formatted string
        if formatted_output is True:

            if end >= 60:
                # Calculated delta is greater than or equal to 1 minute
                output = 'Execution finished in ' + str(round(end, 1)) + ' seconds '
                output += '(' + str(round(end / 60, 2)) + ' minutes)'
            else:
                # Calculated time is less than 1 minute
                output = 'Execution finished in ' + str(round(end, 1)) + ' seconds'
        else:
            # No formatting, just return the raw delta
            output = end

        # Cleanup and return
        del end
        return output

    except AssertionError as e:
        log.exception(e)
        if config.get('general', {}).get('halt_on_error', True) is True:
            sys.exit(1)
        else:
            pass


def exec_convert_bytes(input_bytes):
    """
    Convert raw byte values to human readable formats

    Args:
        input_bytes (int): Raw bytes value to convert

    Returns:
        str: Returns formatted value of input_bytes

    Raises:
        AssertionError: Raises an exception if assertion checks fail
    """

    assert isinstance(input_bytes, int), "Expecting integer for parameter: input_bytes"

    # Courtesy of:
    # https://stackoverflow.com/questions/12523586/python-format-size-application-converting-b-to-kb-mb-gb-tb
    b = int(input_bytes)
    kilobyte = float(1024)
    megabyte = float(kilobyte ** 2)
    gigabyte = float(kilobyte ** 3)
    terabyte = float(kilobyte ** 4)

    if b < kilobyte:
        return '{0} {1}'.format(b, 'Bytes')
    elif kilobyte <= b < megabyte:
        return '{0:.2f} KB'.format(b / kilobyte)
    elif megabyte <= b < gigabyte:
        return '{0:.2f} MB'.format(b / megabyte)
    elif gigabyte <= b < terabyte:
        return '{0:.2f} GB'.format(b / gigabyte)
    elif terabyte <= b:
        return '{0:.2f} TB'.format(b / terabyte)


''' API Classes '''


class Wildfire(object):
    """
    Palo Alto Networks CDSS (Wildfire) Interface Class

    A re-implementation based on work by Sean Whalen: https://github.com/seanthegeek/pyldfire

    Args:
        configuration (dict): Dict containing our configuration parameters

    Raises:
        AssertionError: Raises an assertion error if assertion checks on inputs fail on __init__

    """

    def __init__(self, configuration):

        try:

            # Class called
            log.info('Initialising ' + self.__class__.__name__ + ' Interface Class...')

            # Check configuration is a dict
            assert isinstance(configuration, dict), "Expecting dict for parameter 'configuration'"

            # Copy our configuration into the class namespace
            self.params = configuration['wildfire']

            # Throw a warning message if halt_on_error is False
            halt = configuration.get('general', {}).get('halt_on_error', True)
            if halt is False:
                log.warning('Script is not set to halt/exit on error, this can produce undesired behaviour!')
                self.params['halt'] = False
            else:
                self.params['halt'] = True

            # Set whether or not we should honour TLS verification
            if configuration.get('general', {}).get('tls_verify', True) is False:
                urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
                log.warning('Disabling TLS verification and suppressing notifications!')
                self.params['tls_verify'] = False
            else:
                self.params['tls_verify'] = True

            # Cleanup
            del halt
            del configuration

            # Create the base url
            self.params['base_url'] = 'https://' + self.params.get('host', None) + '/publicapi'

            # Create a dict to store the api response codes
            self.wf_api_response_codes = {
                200: 'OK',
                401: 'Invalid API Key',
                403: 'Forbidden',
                404: 'Not found',
                405: 'Unsupported Method',
                413: 'Request Entity Too Large',
                418: 'Unsupported File Type',
                419: 'Max Request Reached',
                420: 'Insufficient Arguments',
                421: 'Invalid Argument',
                422: 'Unprocessable Entities',
                500: 'Internal Error',
                513: 'File Upload Failed'
            }

            # Create a dict to store the verdict id -> name mappings
            self.wf_api_verdicts = {
                0: 'benign',
                1: 'malware',
                2: 'grayware',
                4: 'phishing',
                5: 'C2',
                -100: 'pending',
                -101: 'error',
                -102: 'not found',
                -103: 'invalid hash',
                4094: 'unknown'
            }

            # Create a dict to store the currently supported Wildfire platforms
            self.wf_supported_platforms = {
                1: 'Windows XP, Adobe Reader 9.3.3, Office 2003',
                2: 'Windows XP, Adobe Reader 9.4.0, Flash 10, Office 2007',
                3: 'Windows XP, Adobe Reader 11, Flash 11, Office 2010',
                4: 'Windows 7 32-bit, Adobe Reader 11, Flash 11, Office 2010',
                5: 'Windows 7 64-bit, Adobe Reader 11, Flash 11, Office 2010',
                6: 'Windows XP, Internet Explorer 8, Flash 11',
                20: 'Windows XP, Adobe Reader 9.4.0, Flash 10, Office 2007',
                21: 'Windows 7, Flash 11, Office 2010',
                50: 'Mac OSX Mountain Lion',
                60: 'Windows XP, Adobe Reader 9.4.0, Flash 10, Office 2007',
                61: 'Windows 7 64-bit, Adobe Reader 11, Flash 11, Office 2010',
                66: 'Windows 10 64-bit, Adobe Reader 11, Flash 22, Office 2010',
                100: 'PDF Static Analyzer',
                101: 'DOC/CDF Static Analyzer',
                102: 'Java/Jar Static Analyzer',
                103: 'Office 2007 Open XML Static Analyzer',
                104: 'Adobe Flash Static Analyzer',
                105: 'RTF Static Analyzer',
                110: 'Max OSX Static Analyzer',
                200: 'APK Static Analyzer',
                201: 'Android 2.3, API 10, avd2.3.1',
                202: 'Android 4.1, API 16, avd4.1.1 X86',
                203: 'Android 4.1, API 16, avd4.1.1 ARM',
                204: 'PE Static Analyzer',
                205: 'Phishing Static Analyzer',
                206: 'Android 4.3, API 18, avd4.3 ARM',
                207: 'Script Static Analyzer',
                300: 'Windows XP, Internet Explorer 8, Flash 13.0.0.281, Flash 16.0.0.305, Elink Analyzer',
                301: 'Windows 7, Internet Explorer 9, Flash 13.0.0.281, Flash 17.0.0.169, Elink Analyzer',
                302: 'Windows 7, Internet Explorer 10, Flash 16.0.0.305, Flash 17.0.0.169, Elink Analyzer',
                303: 'Windows 7, Internet Explorer 11, Flash 16.0.0.305, Flash 17.0.0.169, Elink Analyzer',
                400: 'Linux (ELF Files)',
                403: 'Linux Script Dynamic Analyzer',
                404: 'Linux Script Static Analyzer',
                501: 'BareMetal Windows 7 x64, Adobe Reader 11, Flash 11, Office 2010',
                800: 'Archives (RAR and 7-Zip files)'
            }

            # Create a dict to store the verdict name -> id mappings
            self.wf_api_verdict_ids = dict((value, key) for key, value in self.wf_api_verdicts.items())

            # Log class parameters to debug
            log.debug(separator_half)
            log.debug('Class Variables:            ' + str(self.params))
            log.debug('WF API Response Codes:      ' + str(self.wf_api_response_codes))
            log.debug('WF API Verdicts (ID->Name): ' + str(self.wf_api_verdicts))
            log.debug('WF API Verdicts (Name->ID): ' + str(self.wf_api_verdict_ids))
            log.debug('WF Supported Platforms:     ' + str(self.wf_supported_platforms))
            log.debug(separator_half)

            # Disable warnings about insecure/self-signed certificates if desired
            if self.params.get('general', {}).get('tls_verify', True) is False:
                urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
                log.warning('Disabling TLS verification and suppressing notifications!')

            # Create success message, __init__ doesn't return anything
            log.info('Initialised ' + self.__class__.__name__ + ' Interface Class')

        except (AssertionError, Exception) as e:
            self.handle_error(e)

    ''' API response validation, debug outputs and error handling '''

    def handle_error(self, e):
        """
        Handles an error thrown by the api or function

        Args:
            e: The exception

        """

        # Should we halt on error?
        halt = self.params.get('halt', True)

        if halt is True:
            log.error('Halting script execution')

        # Log the exception
        log.exception(e)

        # Check if we are exiting/halting on an error

        if halt is True:
            sys.exit(1)
        else:
            # Don't exit/halt, just pass
            log.warning('Script is not set to halt/exit on error, continuing with execution...')
            pass

    def api_validate_response(self, response):
        """
        Validates the response from the API

        Args:
            response: The requests object

        Returns:
            bool: Returns True if valid, False if not

        """
        try:

            log.info('Validating response...')
            r_code = response.status_code
            log.debug('HTTP status code from api is ' + str(r_code))

            if r_code == 200:
                log.info('Got status code 200 [OK] from API')
                return True
            else:
                r_reason = self.wf_api_response_codes.get(r_code, 'Unknown Error')
                log.error(response.text.strip())
                raise Exception('Received error from the API: [' + str(r_code) + '] ' + r_reason)

        except Exception as e:
            self.handle_error(e)
            return False

    def get_wf_api_response_codes(self):
        """
        Returns the response codes from the Wildfire API

        Returns:
            wf_api_response_codes (dict): A dict containing the API response codes

        """
        return self.wf_api_response_codes

    def get_wf_api_verdicts(self):
        """
        Returns the verdicts (ID->Name) from the Wildfire API

        Returns:
            wf_api_verdicts (dict): A dict containing the verdicts (ID->Name) mapping

        """
        return self.wf_api_verdicts

    def get_wf_api_verdicts_name_to_id(self):
        """
        Returns the verdicts (Name->ID) from the Wildfire API

        Returns:
            wf_api_verdict_ids (dict): A dict containing the verdicts (Name->ID) mapping

        """
        return self.wf_api_verdict_ids

    def get_wf_supported_platforms(self):
        """
        Returns the supported platforms within Wildfire

        Returns:
            wf_supported_platforms (dict): A dict containing the supported platforms

        """
        return self.wf_supported_platforms

    ''' Fetch verdict data '''

    def get_verdict(self, file_hash):
        """
        Get Verdict - Attempts to fetch the verdict information for a given hash

        Args:
            file_hash (str): MD5/SHA1/SHA256 hash

        Returns:
            xml (dict): Returns the XML response from the API as an xmltodict object

        """
        try:

            # Check if our input variable is a string
            assert isinstance(file_hash, str), "Expecting string for parameter 'file_hash'"

            # Check if our string inputs are empty
            assert file_hash != '', "Parameter: 'file_hash' cannot be empty!"

            # Construct request URL
            base_url = self.params.get('base_url', None)
            request_url = base_url + '/get/verdict'

            # Construct payload - headers
            headers = {'User-Agent': 'Mozilla/5.0'}

            # Construct payload - data payload
            data = {
                'apikey': self.params.get('api_key', None),
                'hash': file_hash
            }

            log.debug('Constructed request URL as: ' + request_url)
            log.debug('Constructed data dict as: ' + str(data))

            # Send the request to the API
            log.info('Getting verdict for hash: ' + file_hash)
            response = requests.post(request_url,
                                     data=data,
                                     headers=headers,
                                     verify=self.params.get('tls_verify', True)
                                     )

            # Validate our API response
            valid = self.api_validate_response(response)

            if valid is True:

                # Output some debug data
                log.debug(separator_half)
                log.debug('XML Response: ' + response.text.strip().lower())
                log.debug(separator_half)

                # Load into XMLtoDict
                xml = xmltodict.parse(response.content)
                xml_root = xml.get('wildfire', {}).get('get-verdict-info', None)

                # Map the response values
                r_md5 = str(xml_root.get('md5', None))
                r_sha1 = str(xml_root.get('sha1', None))
                r_sha256 = str(xml_root.get('sha256', None))
                r_verdict_raw = str(xml_root.get('verdict', 4094))
                r_verdict_parsed = self.wf_api_verdicts.get(int(r_verdict_raw), 'Script Error').capitalize()

                # Output to system
                log.info(separator_half)
                log.info('MD5:     ' + r_md5)
                log.info('SHA1:    ' + r_sha1)
                log.info('SHA256:  ' + r_sha256)
                log.info('Verdict: ' + r_verdict_raw + ' (' + r_verdict_parsed + ')')
                log.info(separator_half)

                # Return XML object
                return xml

            else:
                raise Exception('Could not get verdict information for hash: ' + file_hash)

        except (AssertionError, Exception) as e:
            self.handle_error(e)

    def get_verdicts(self, file_hashes):
        """
        Get Verdicts - Attempts to fetch the verdicts information for a given hash

        Args:
            file_hashes (list): MD5/SHA1/SHA256 hash list

        Returns:
            xml (dict): Returns the XML response from the API as an xmltodict object

        """
        try:
            # Check if our input variable is a list
            assert isinstance(file_hashes, list), "Expecting list for parameter 'file_hashes'"

            # Check if our list is empty
            if len(file_hashes) == 0:
                raise Exception('Passed list input cannot be empty!')

            # Check if the list contains only one item, redirect to the get_verdict function
            if len(file_hashes) == 1:
                xml = self.get_verdict(file_hashes[0])
                return xml

            # Construct request URL
            base_url = self.params.get('base_url', None)
            request_url = base_url + '/get/verdicts'

            # Construct payload - headers
            headers = {'User-Agent': 'Mozilla/5.0'}

            # Construct payload - data payload
            data = {
                'apikey': self.params.get('api_key', None),
            }

            # Construct payload, list entries to a mock in-memory file
            files = dict(file=("hashes", io.BytesIO(bytes('\n'.join(file_hashes), 'ascii'))))

            # Debug output
            log.debug('Constructed request URL as: ' + request_url)
            log.debug('Constructed data dict as: ' + str(data))
            log.debug('Constructed files dict as: ' + str(files))

            # Send the request to the API
            log.info('Getting verdicts for ' + str(len(file_hashes)) + ' hashes')
            response = requests.post(request_url,
                                     data=data,
                                     headers=headers,
                                     files=files,
                                     verify=self.params.get('tls_verify', True)
                                     )

            # Validate our API response
            valid = self.api_validate_response(response)

            if valid is True:

                # Output some debug data
                log.debug(separator_half)
                log.debug('XML Response: ' + response.text.strip().lower())
                log.debug(separator_half)

                # Load into XMLtoDict
                xml = xmltodict.parse(response.content)
                xml = xml.get('wildfire', {}).get('get-verdict-info', None)

                if xml is None:
                    raise Exception('Could not iterate through XML response: ' + str(xml))
                else:

                    # Start a counter to denote our position in the passed list
                    i = 0

                    # Loop through entries
                    for entry in xml:
                        # Map the response values
                        r_md5 = str(entry.get('md5', None))
                        r_sha1 = str(entry.get('sha1', None))
                        r_sha256 = str(entry.get('sha256', None))
                        r_verdict_raw = str(entry.get('verdict', 4094))
                        r_verdict_parsed = self.wf_api_verdicts.get(int(r_verdict_raw), 'Script Error').capitalize()

                        # Output to system
                        log.info(separator_half)
                        log.info('List ID: ' + str(i))
                        log.info('MD5:     ' + r_md5)
                        log.info('SHA1:    ' + r_sha1)
                        log.info('SHA256:  ' + r_sha256)
                        log.info('Verdict: ' + r_verdict_raw + ' (' + r_verdict_parsed + ')')

                        # Increment counter by 1
                        i += 1

                    # End of for loop
                    log.info(separator_half)

                    # Return XML object
                    return xml

            else:
                raise Exception('Could not get verdict information for hashes: ' + str(file_hashes))

        except (AssertionError, Exception) as e:
            self.handle_error(e)

    ''' Submit files and links to Wildfire '''

    def submit_local_file(self, file):
        """
        Submits a local file to Wildfire

        Args:
            file (str): The file to send for inspection

        Returns:
            xml (dict): Returns the XML response from the API as an xmltodict object

        """
        try:

            # Check if our input variable is a string
            assert isinstance(file, str), "Expecting string for parameter 'file'"

            # Check if our string inputs are empty
            assert file != '', "Parameter: 'file' cannot be empty!"

            # Construct request URL
            base_url = self.params.get('base_url', None)
            request_url = base_url + '/submit/file'

            # Construct payload - headers
            headers = {'User-Agent': 'Mozilla/5.0'}

            # Construct payload - data payload
            data = {
                'apikey': self.params.get('api_key', None),
            }

            # Open file
            log.info('Attempting to read file: ' + file)
            with open(file, 'rb') as sample_file:

                # Get the file name
                name = os.path.basename(sample_file.name)

                # Construct payload, create file object to send
                files = dict(file=(name, sample_file))

                log.debug('Constructed request URL as: ' + request_url)
                log.debug('Constructed data dict as: ' + str(data))
                log.debug('Constructed files dict as: ' + str(files))

                # Send the request to the API
                log.info('Submitting ' + name + ' to Wildfire...')
                response = requests.post(request_url,
                                         data=data,
                                         headers=headers,
                                         files=files,
                                         verify=self.params.get('tls_verify', True)
                                         )

                # Validate our API response
                valid = self.api_validate_response(response)

                if valid is True:

                    # Output some debug data
                    log.debug(separator_half)
                    log.debug('XML Response: ' + response.text.strip().lower())
                    log.debug(separator_half)

                    # Load into XMLtoDict
                    xml = xmltodict.parse(response.content)
                    xml_root = xml.get('wildfire', {}).get('upload-file-info', None)

                    if xml_root is None:
                        raise Exception('Could not iterate over xml response: ' + str(xml))
                    else:

                        # Map the response values
                        r_url = str(xml_root.get('url', None))
                        r_type = str(xml_root.get('filetype', None))
                        r_name = str(xml_root.get('filename', None))
                        r_md5 = str(xml_root.get('md5', None))
                        r_sha1 = str(xml_root.get('sha1', None))
                        r_sha256 = str(xml_root.get('sha256', None))
                        r_size = str(xml_root.get('size', None))

                        # Output to system
                        log.info(separator_half)
                        log.info('URL:       ' + r_url)
                        log.info('MD5:       ' + r_md5)
                        log.info('SHA1:      ' + r_sha1)
                        log.info('SHA256:    ' + r_sha256)
                        log.info('File Name: ' + r_name)
                        log.info('File Type: ' + r_type)
                        log.info('File Size: ' + r_size + ' Bytes (' + exec_convert_bytes(int(r_size)) + ')')
                        log.info(separator_half)

                        # Return XML object
                        return xml

                else:
                    raise Exception('Could not validate API response')

        except (AssertionError, Exception) as e:
            self.handle_error(e)

    def submit_remote_file(self, file):
        """
        Submits a file at a remote location to Wildfire
        e.g. http://mywebsite.com/pub/mysample.exe

        Args:
            file (str): The file to send for inspection

        Returns:
            xml (dict): Returns the XML response from the API as an xmltodict object

        """
        try:

            # Check if our input variable is a string
            assert isinstance(file, str), "Expecting string for parameter 'file'"

            # Check if our string inputs are empty
            assert file != '', "Parameter: 'file' cannot be empty!"

            # Construct request URL
            base_url = self.params.get('base_url', None)
            request_url = base_url + '/submit/url'

            # Construct payload - headers
            headers = {'User-Agent': 'Mozilla/5.0'}

            # Construct payload - data payload
            data = {
                'apikey': self.params.get('api_key', None),
                'url': file
            }

            log.debug('Constructed request URL as: ' + request_url)
            log.debug('Constructed data dict as: ' + str(data))

            # Send the request to the API
            log.info('Submitting ' + file + ' to Wildfire...')
            response = requests.post(request_url,
                                     data=data,
                                     headers=headers,
                                     verify=self.params.get('tls_verify', True)
                                     )

            # Validate our API response
            valid = self.api_validate_response(response)

            if valid is True:

                # Output some debug data
                log.debug(separator_half)
                log.debug('XML Response: ' + response.text.strip().lower())
                log.debug(separator_half)

                # Load into XMLtoDict
                xml = xmltodict.parse(response.content)
                xml_root = xml.get('wildfire', {}).get('upload-file-info', None)

                if xml_root is None:
                    raise Exception('Could not iterate over xml response: ' + str(xml))
                else:

                    # Map the response values
                    r_url = str(xml_root.get('url', None))
                    r_type = str(xml_root.get('filetype', None))
                    r_name = str(xml_root.get('filename', None))
                    r_md5 = str(xml_root.get('md5', None))
                    r_sha1 = str(xml_root.get('sha1', None))
                    r_sha256 = str(xml_root.get('sha256', None))
                    r_size = str(xml_root.get('size', None))

                    # Output to system
                    log.info(separator_half)
                    log.info('URL:       ' + r_url)
                    log.info('MD5:       ' + r_md5)
                    log.info('SHA1:      ' + r_sha1)
                    log.info('SHA256:    ' + r_sha256)
                    log.info('File Name: ' + r_name)
                    log.info('File Type: ' + r_type)
                    log.info('File Size: ' + r_size + ' Bytes (' + exec_convert_bytes(int(r_size)) + ')')
                    log.info(separator_half)

                    # Return XML object
                    return xml

            else:
                raise Exception('Could not validate API response')

        except (AssertionError, Exception) as e:
            self.handle_error(e)

    def submit_url(self, url):
        """
        Submits a single URL for inspection

        Args:
            url (str): The url to send for inspection

        Returns:
            xml (dict): Returns the XML response from the API as an xmltodict object

        """
        try:

            # Check if our input variable is a string
            assert isinstance(url, str), "Expecting string for parameter 'url'"

            # Check if our string inputs are empty
            assert url != '', "Parameter: 'url' cannot be empty!"

            # Construct request URL
            base_url = self.params.get('base_url', None)
            request_url = base_url + '/submit/link'

            # Construct payload - headers
            headers = {'User-Agent': 'Mozilla/5.0'}

            # Construct payload - data payload
            data = {
                'apikey': self.params.get('api_key', None),
                'link': str(url).strip()
            }

            log.debug('Constructed request URL as: ' + request_url)
            log.debug('Constructed data dict as: ' + str(data))

            # Send the request to the API
            log.info('Submitting ' + url + ' to Wildfire...')
            response = requests.post(request_url,
                                     data=data,
                                     headers=headers,
                                     verify=self.params.get('tls_verify', True)
                                     )

            # Validate our API response
            valid = self.api_validate_response(response)

            if valid is True:

                # Output some debug data
                log.debug(separator_half)
                log.debug('XML Response: ' + response.text.strip().lower())
                log.debug(separator_half)

                # Load into XMLtoDict
                xml = xmltodict.parse(response.content)
                xml_root = xml.get('wildfire', {}).get('submit-link-info', None)

                if xml_root is None:
                    raise Exception('Could not iterate over xml response: ' + str(xml))
                else:

                    # Map the response values
                    r_url = str(xml_root.get('url', None))
                    r_md5 = str(xml_root.get('md5', None))
                    r_sha1 = str(xml_root.get('sha1', None))
                    r_sha256 = str(xml_root.get('sha256', None))

                    # Output to system
                    log.info(separator_half)
                    log.info('URL:       ' + r_url)
                    log.info('MD5:       ' + r_md5)
                    log.info('SHA1:      ' + r_sha1)
                    log.info('SHA256:    ' + r_sha256)
                    log.info(separator_half)

                    # Return XML object
                    return xml

            else:
                raise Exception('Could not validate API response')

        except (AssertionError, Exception) as e:
            self.handle_error(e)

    def submit_urls(self, urls):
        """
        Submits a list of URL's for inspection

        Args:
            urls (list): The url to send for inspection

        Returns:
            xml (dict): Returns the XML response from the API as an xmltodict object

        """
        try:

            # Check if our input variable is a string
            assert isinstance(urls, list), "Expecting string for parameter 'urls'"

            # Check if our list inputs are empty
            if len(urls) == 0:
                raise Exception('Input list (urls) cannot be empty!')

            # Check if the list contains only one item, redirect to the get_verdict function
            if len(urls) == 1:
                xml = self.submit_url(urls[0])
                return xml

            # Check if our list is bigger than permitted (1000)
            if len(urls) > 1000:
                raise Exception('Maximum number of supported URL\'s is 1000, list has ' + str(len(urls)))

            # Construct request URL
            base_url = self.params.get('base_url', None)
            request_url = base_url + '/submit/links'

            # Construct payload - headers
            headers = {'User-Agent': 'Mozilla/5.0'}

            # Construct payload - data payload
            data = {
                'apikey': self.params.get('api_key', None)
            }

            # Add required "panlnk" identifier to the start of the file list
            urls.insert(0, 'panlnk')

            # Construct payload, list entries to a mock in-memory file
            files = dict(file=("hashes", io.BytesIO(bytes('\n'.join(urls), 'ascii'))))

            # Debug output
            log.debug('Constructed request URL as: ' + request_url)
            log.debug('Constructed data dict as: ' + str(data))
            log.debug('Constructed files dict as: ' + str(files))

            # Send the request to the API
            log.info('Submitting ' + str(len(urls)) + ' URL\'s to Wildfire...')
            response = requests.post(request_url,
                                     data=data,
                                     headers=headers,
                                     verify=self.params.get('tls_verify', True)
                                     )

            # Validate our API response
            valid = self.api_validate_response(response)

            if valid is True:

                # Output some debug data
                log.debug(separator_half)
                log.debug('XML Response: ' + response.text.strip().lower())
                log.debug(separator_half)

                # Load into XMLtoDict
                xml = xmltodict.parse(response.content)
                xml = xml.get('wildfire', {}).get('submit-link-info', None)

                if xml is None:
                    raise Exception('Could not iterate through XML response: ' + str(xml))
                else:

                    # Start a counter to denote our position in the passed list
                    i = 0

                    # Loop through entries
                    for entry in xml:
                        # Map the response values
                        r_url = str(entry.get('url', None))
                        r_md5 = str(entry.get('md5', None))
                        r_sha1 = str(entry.get('sha1', None))
                        r_sha256 = str(entry.get('sha256', None))

                        # Output to system
                        log.info(separator_half)
                        log.info('List ID: ' + str(i))
                        log.info('URL:     ' + r_url)
                        log.info('MD5:     ' + r_md5)
                        log.info('SHA1:    ' + r_sha1)
                        log.info('SHA256:  ' + r_sha256)

                        # Increment counter by 1
                        i += 1

                    # End of for loop
                    log.info(separator_half)

                    # Return XML object
                    return xml

            else:
                raise Exception('Could not validate API response')

        except (AssertionError, Exception) as e:
            self.handle_error(e)

    ''' Reporting - File (hash) based '''

    def _worker_get_report_hash(self, file_hash, report_format):
        """
        An internal worker function to actually get the report data from Wildfire

        Args:
            file_hash (str): MD5/SHA1/SHA256 hash
            report_format (str): PDF or XML

        Returns:
            xml (dict): Returns the XML response from the API as an xmltodict object
            pdf (bytes): Returns the raw bytes for the PDF report

        """

        try:

            # Check if our input variable is a string
            assert isinstance(file_hash, str), "Expecting string for parameter 'file_hash'"
            assert isinstance(report_format, str), "Expecting string for parameter 'report_format'"

            # Check if our string inputs are empty
            assert file_hash != '', "Parameter: 'file_hash' cannot be empty!"
            assert report_format != '', "Parameter: 'report_format' cannot be empty!"

            # Check input against our supported operating modes
            if report_format not in ['pdf', 'xml']:
                raise Exception('Only PDF or XML formats are supported, requested: ' + report_format)

            # Construct request URL
            base_url = self.params.get('base_url', None)
            request_url = base_url + '/get/report'

            # Construct payload - headers
            headers = {'User-Agent': 'Mozilla/5.0'}

            # Construct payload - data payload
            data = {
                'apikey': self.params.get('api_key', None),
                'hash': file_hash,
                'format': report_format
            }

            # If PDF is requested, enable streaming of data
            if report_format == 'pdf':
                stream = True
            else:
                stream = False

            # Send the request to the API
            log.info('Getting report for hash: ' + file_hash + ' with output: ' + report_format)
            response = requests.post(
                request_url,
                data=data,
                headers=headers,
                stream=stream,
                verify=self.params.get('tls_verify', True)
            )

            # Validate the response
            valid = self.api_validate_response(response)

            if valid is True:
                # If PDF is requested, return the bytes, if XML, parse it and return the XML
                if report_format == 'pdf':
                    return response.content

                else:

                    # Output some debug data
                    log.debug(separator_half)
                    log.debug('XML Response: ' + response.text.strip().lower())
                    log.debug(separator_half)

                    # Load into XMLtoDict
                    xml = xmltodict.parse(response.content)
                    xml = xml.get('wildfire', None)
                    log.debug('XML Response: ' + str(xml))

                    # Return XML data
                    return xml
            else:
                raise Exception('Could not download file: ' + request_url)

        except (AssertionError, Exception) as e:
            self.handle_error(e)

    def get_pdf_report_by_hash(self, file_hash):
        """
        Get's the PDF report data from Wildfire based on a hash

        Args:
            file_hash (str): MD5/SHA1/SHA256 hash

        Returns:
            pdf (bytes): Returns the raw bytes for the PDF report

        """

        try:

            # Check if our input variable is a string
            assert isinstance(file_hash, str), "Expecting string for parameter 'file_hash'"

            # Check if our string inputs are empty
            assert file_hash != '', "Parameter: 'file_hash' cannot be empty!"

            pdf = self._worker_get_report_hash(file_hash, 'pdf')
            return pdf

        except (AssertionError, Exception) as e:
            self.handle_error(e)

    def get_xml_report_by_hash(self, file_hash):
        """
        Get's the XML report from Wildfire based on a hash

        Args:
            file_hash (str): MD5/SHA1/SHA256 hash

        Returns:
            xml (dict): Returns the XML data as a parsed dict

        """

        try:

            # Check if our input variable is a string
            assert isinstance(file_hash, str), "Expecting string for parameter 'file_hash'"

            # Check if our string inputs are empty
            assert file_hash != '', "Parameter: 'file_hash' cannot be empty!"

            xml = self._worker_get_report_hash(file_hash, 'xml')
            return xml

        except (AssertionError, Exception) as e:
            self.handle_error(e)

    ''' Reporting - URL based'''

    def _worker_get_report_url(self, url):
        """
        An internal worker function to actually get the report data from Wildfire

        Args:
            url (str): The URL to query

        Returns:
            json_data (json): Returns the JSON response from the API

        """

        try:

            # Check if our input variable is a string
            assert isinstance(url, str), "Expecting string for parameter 'url'"

            # Check if our string inputs are empty
            assert url != '', "Parameter: 'url' cannot be empty!"

            # Construct request URL
            base_url = self.params.get('base_url', None)
            request_url = base_url + '/get/report'

            # Construct payload - headers
            headers = {'User-Agent': 'Mozilla/5.0'}

            # Construct payload - data payload
            data = {
                'apikey': self.params.get('api_key', None),
                'url': url,
            }

            # Send the request to the API
            log.info('Getting report for url: ' + url)
            response = requests.post(
                request_url,
                data=data,
                headers=headers,
                verify=self.params.get('tls_verify', True)
            )

            # Validate the response
            valid = self.api_validate_response(response)

            if valid is True:

                # Load the JSON response
                json_data = response.json()
                log.debug(separator_half)
                log.debug('JSON response: ' + str(json_data))
                log.debug(separator_half)
                return json_data
            else:
                raise Exception('Could not download file: ' + request_url)

        except (AssertionError, Exception) as e:
            self.handle_error(e)

    def get_report_by_url(self, url):
        """
        Get's the JSON report data for a given URL

        Args:
            url (str): The URL to query

        Returns:
            json_data (dict): Returns the raw bytes for the PDF report

        """

        try:

            # Check if our input variable is a string
            assert isinstance(url, str), "Expecting string for parameter 'url'"

            # Check if our string inputs are empty
            assert url != '', "Parameter: 'url' cannot be empty!"

            json_data = self._worker_get_report_url(url)
            return json_data

        except (AssertionError, Exception) as e:
            self.handle_error(e)

    ''' Download samples, pcaps and test files '''

    def get_sample(self, file_hash):
        """
        Downloads a sample from Wildfire

        Args:
            file_hash (str): MD5/SHA1/SHA256 hash

        Returns:
            data (bytes): The raw bytes of the sample

        """
        try:

            # Check if our input variable is a string
            assert isinstance(file_hash, str), "Expecting string for parameter 'file_hash'"

            # Check if our string inputs are empty
            assert file_hash != '', "Parameter: 'file_hash' cannot be empty!"

            # Construct request URL
            base_url = self.params.get('base_url', None)
            request_url = base_url + '/get/sample'

            # Construct payload - headers
            headers = {'User-Agent': 'Mozilla/5.0'}

            # Construct payload - data payload
            data = {
                'apikey': self.params.get('api_key', None),
                'hash': file_hash
            }

            # Send the request to the API
            log.info('Downloading data for hash: ' + file_hash)
            response = requests.post(
                request_url,
                data=data,
                headers=headers,
                stream=True,
                verify=self.params.get('tls_verify', True)
            )

            # Validate the response
            valid = self.api_validate_response(response)

            if valid is True:
                data = response.content
                return data
            else:
                raise Exception('Could not download file: ' + request_url)

        except (AssertionError, Exception) as e:
            self.handle_error(e)

    def get_pcap(self, file_hash, platform=None):
        """
        Downloads a sample from Wildfire

        Args:
            file_hash (str): MD5/SHA1/SHA256 hash
            platform (int): A specific platform if desired

        Returns:
            data (bytes): The raw bytes of the sample

        Supported Platforms:
            This list is correct as of 01/04/2021 - Please check the docs and update accordingly

            WildFire Private and Global Cloud
                1: Windows XP, Adobe Reader 9.3.3, Office 2003
                2: Windows XP, Adobe Reader 9.4.0, Flash 10, Office 2007
                3: Windows XP, Adobe Reader 11, Flash 11, Office 2010
                4: Windows 7 32-bit, Adobe Reader 11, Flash 11, Office 2010
                5: Windows 7 64-bit, Adobe Reader 11, Flash 11, Office 2010
                100: PDF Static Analyzer
                101: DOC/CDF Static Analyzer
                102: Java/Jar Static Analyzer
                103: Office 2007 Open XML Static Analyzer
                104: Adobe Flash Static Analyzer
                204: PE Static Analyzer
                800: Archives (RAR and 7-Zip files)

            WildFire Global Cloud only
                6: Windows XP, Internet Explorer 8, Flash 11
                20: Windows XP, Adobe Reader 9.4.0, Flash 10, Office 2007
                21: Windows 7, Flash 11, Office 2010
                50: Mac OSX Mountain Lion
                60: Windows XP, Adobe Reader 9.4.0, Flash 10, Office 2007
                61: Windows 7 64-bit, Adobe Reader 11, Flash 11, Office 2010
                66: Windows 10 64-bit, Adobe Reader 11, Flash 22, Office 2010
                105: RTF Static Analyzer
                110: Max OSX Static Analyzer
                200: APK Static Analyzer
                201: Android 2.3, API 10, avd2.3.1
                202: Android 4.1, API 16, avd4.1.1 X86
                203: Android 4.1, API 16, avd4.1.1 ARM
                205: Phishing Static Analyzer
                206: Android 4.3, API 18, avd4.3 ARM
                207: Script Static Analyzer
                300: Windows XP, Internet Explorer 8, Flash 13.0.0.281, Flash 16.0.0.305, Elink Analyzer
                301: Windows 7, Internet Explorer 9, Flash 13.0.0.281, Flash 17.0.0.169, Elink Analyzer
                302: Windows 7, Internet Explorer 10, Flash 16.0.0.305, Flash 17.0.0.169, Elink Analyzer
                303: Windows 7, Internet Explorer 11, Flash 16.0.0.305, Flash 17.0.0.169, Elink Analyzer
                400: Linux (ELF Files)
                403: Linux Script Dynamic Analyzer
                404: Linux Script Static Analyzer
                501: BareMetal Windows 7 x64, Adobe Reader 11, Flash 11, Office 2010

        """
        try:

            # Check if our input variable is a string
            assert isinstance(file_hash, str), "Expecting string for parameter 'file_hash'"

            # Check if our string inputs are empty
            assert file_hash != '', "Parameter: 'file_hash' cannot be empty!"

            # Check if we are defining a specific platform
            if platform is not None:
                assert isinstance(platform, int), "Expecting integer for parameter 'platform'"

                # Check if the requested platform is in the supported list
                if platform not in self.wf_supported_platforms:
                    raise Exception('Unsupported platform requested!')

            # Construct request URL
            base_url = self.params.get('base_url', None)
            request_url = base_url + '/get/pcap'

            # Construct payload - headers
            headers = {'User-Agent': 'Mozilla/5.0'}

            # Construct payload - data payload
            data = {
                'apikey': self.params.get('api_key', None),
                'hash': file_hash
            }

            # Add our platform if specified
            if platform is not None:
                data['platform'] = platform

            # Send the request to the API
            log.info('Downloading PCAP data for hash: ' + file_hash)
            response = requests.post(
                request_url,
                data=data,
                headers=headers,
                stream=True,
                verify=self.params.get('tls_verify', True)
            )

            # Validate the response
            valid = self.api_validate_response(response)

            if valid is True:
                data = response.content
                return data
            else:
                raise Exception('Could not download file: ' + request_url)

        except (AssertionError, Exception) as e:
            self.handle_error(e)

    def get_web_artifacts(self, url, types=None):
        """
        Downloads the web artifacts for a given url
        You will need to save the bytes output from this function to a .tar.gz archive

        Args:
            url (str): The URL to query
            types (str): Optional, default is all, options are: screenshot, download_files

        Returns:
            data (bytes): The raw bytes of the sample

        """
        try:

            # Check if our input variable is a string
            assert isinstance(url, str), "Expecting string for parameter 'url'"

            # Check if our string inputs are empty
            assert url != '', "Parameter: 'url' cannot be empty!"

            # Check if types has been specified
            if types is not None:
                # Check if our input variable is a string and is not empty
                assert isinstance(types, str), "Expecting string for parameter 'url'"
                assert types != '', "Parameter: 'url' cannot be empty!"

            # Construct request URL
            base_url = self.params.get('base_url', None)
            request_url = base_url + '/get/webartifacts'

            # Construct payload - headers
            headers = {'User-Agent': 'Mozilla/5.0'}

            # Construct payload - data payload
            data = {
                'apikey': self.params.get('api_key', None),
                'url': url
            }

            if types is not None:
                data['types'] = types

            # Send the request to the API
            log.info('Downloading web artifacts data for URL: ' + url)
            response = requests.post(
                request_url,
                data=data,
                headers=headers,
                stream=True,
                verify=self.params.get('tls_verify', True)
            )

            # Validate the response
            valid = self.api_validate_response(response)

            if valid is True:
                data = response.content
                return data
            else:
                raise Exception('Could not download file: ' + request_url)

        except (AssertionError, Exception) as e:
            self.handle_error(e)

    def get_test_file(self, ssl_tls, platform):
        """
        Downloads a sample from Wildfire

        Args:
            ssl_tls (bool): Download over TLS (True) or plaintext (False)
            platform (str): A specific platform (win32_64/macos/android/linux)

        Returns:
            data (bytes): The raw bytes of the sample

        """
        try:

            # Check if our input variable is a string
            assert isinstance(ssl_tls, bool), "Expecting boolean for parameter 'ssl_tls'"
            assert isinstance(platform, str), "Expecting string for parameter 'platform'"

            # Check if our string inputs are empty
            assert platform != '', "Parameter: 'platform' cannot be empty!"

            # Check if we are defining a specific platform
            supported_platforms = ['win32_64', 'macos', 'android', 'linux']
            if platform not in supported_platforms:
                raise Exception('Unsupported platform requested, support platforms: ' + str(supported_platforms))

            # Construct our base url
            if ssl_tls is True:
                http_uri = 'https://'
            else:
                http_uri = 'http://'

            # Add our base host to the base_url
            base_url = http_uri + self.params.get('host', None) + '/publicapi'

            # Construct request URL
            request_url = base_url + '/test/'

            # Append the file-type to the request_url based on platform
            if platform == 'win32_64':
                request_url += 'pe'

            if platform == 'macos':
                request_url += 'macos'

            if platform == 'android':
                request_url += 'apk'

            if platform == 'linux':
                request_url += 'elf'

            # Construct payload - headers
            headers = {'User-Agent': 'Mozilla/5.0'}

            # Send the request to the API
            log.info('Attempting to download ' + platform + ' malware test file from: ' + request_url)
            response = requests.post(
                request_url,
                headers=headers,
                stream=True,
                verify=self.params.get('tls_verify', True)
            )

            # Validate the response
            valid = self.api_validate_response(response)

            if valid is True:
                data = response.content
                return data
            else:
                raise Exception('Could not download file: ' + request_url)

        except (AssertionError, Exception) as e:
            self.handle_error(e)


''' Main '''


def main():
    """
    Main - Serves as an entry point into the application
    """
    try:
        log.info(separator)

        # Store some SHA256 hashes
        hashes = ['7e7b70a80ecc991ee4ed0b49633074fe88a4456cd69db22b6eb9501c55b5c54d',
                  '886ad4234b07428792f285f400cb83082fb34ec70eae8e3f567a469a7cd05f7f',
                  '984bf91d1828ec9cff53e3df6812a22f1d88fc20bfd828d776ff8921061590bd',
                  '36a797f391c0783883a1f2b1228fe668295247847f0949bf951dac72d9f2462a']

        # Store some URL's for testing
        urls = [
            'https://google.com',
            'https://facebook.com',
            'https://twitter.com',
            'https://microsoft.com'
        ]

        # Store a remote file to submit to Wildfire (Portable 7Zip)
        remote_file = 'https://download3.portableapps.com/portableapps/7-ZipPortable/7-ZipPortable_19.00_Rev_3.paf.exe'

        ''' Wildfire Use-Cases '''

        # Create our WildFire interface
        wildfire = Wildfire(config)

        # Get single verdict
        single_verdict = wildfire.get_verdict(hashes[0])
        log.info(separator_half)
        log.info('Verdict for: ' + hashes[0])
        log.info(single_verdict)

        # Get multiple verdicts
        multiple_verdicts = wildfire.get_verdicts(hashes)
        log.info(multiple_verdicts)

        # Submit local file to Wildfire
        submit_local_file = wildfire.submit_local_file('sample.exe')
        log.info(submit_local_file)

        # Submit remote file to Wildfire
        submit_remote_file = wildfire.submit_remote_file(remote_file)
        log.info(submit_remote_file)

        # Submit URL to Wildfire
        submit_url = wildfire.submit_url(urls[0])
        log.info(submit_url)

        # Submit URL's to Wildfire for analysis
        submit_urls = wildfire.submit_urls(urls)
        log.info(submit_urls)

        # Get PDF report for a given sample
        pdf_report_data = wildfire.get_pdf_report_by_hash(hashes[3])
        with open(hashes[3] + '.pdf', 'wb') as file_data:
            file_data.write(pdf_report_data)

        # Get XML report for a given sample
        xml_report_data = wildfire.get_xml_report_by_hash(hashes[3])
        print(xml_report_data)

        # Get report for an analysed URL
        url_report = wildfire.get_report_by_url(urls[0])
        for key, value in url_report.items():
            print(key, '-->', value)

        # Download Wildfire samples
        files = {
            'sample_0': wildfire.get_sample(hashes[0]),
            'sample_1': wildfire.get_sample(hashes[1]),
            'sample_2': wildfire.get_sample(hashes[2]),
            'sample_3': wildfire.get_sample(hashes[3])
        }

        for key, value in files.items():
            with open(key, 'wb') as file_data:
                file_data.write(value)

        # Download PCAP for a given hash
        pcap_data = wildfire.get_pcap(hashes[3])
        with open('sample_pcap.pcap', 'wb') as file_data:
            file_data.write(pcap_data)

        # Download the web artifacts found by Wildfire for a given URL
        web_artifacts_data = wildfire.get_web_artifacts('http://google.com')
        with open('web_artifacts.tar.gz', 'wb') as file_data:
            file_data.write(web_artifacts_data)

        # Download the various Wildfire test files over HTTP and HTTPS for each platform
        files = {
            'wf_test_win32_64_http.exe': wildfire.get_test_file(False, 'win32_64'),
            'wf_test_win32_64_https.exe': wildfire.get_test_file(True, 'win32_64'),
            'wf_test_macos_http': wildfire.get_test_file(False, 'macos'),
            'wf_test_macos_https': wildfire.get_test_file(True, 'macos'),
            'wf_test_android_http.apk': wildfire.get_test_file(False, 'android'),
            'wf_test_android_https.apk': wildfire.get_test_file(True, 'android'),
            'wf_test_linux_http': wildfire.get_test_file(False, 'linux'),
            'wf_test_linux_https': wildfire.get_test_file(True, 'linux')
        }

        for key, value in files.items():
            with open(key, 'wb') as file_data:
                file_data.write(value)

        log.info(separator)
        log.info(exec_calc_exec_time(start))
        log.info(separator)
        sys.exit(0)

    except Exception as e:
        log.exception(e)
        if config.get('halt_on_error', True) is True:
            sys.exit(1)
        else:
            pass


''' Entry '''

if __name__ in ['__main__', 'builtin', 'builtins']:

    # Capture the start time
    start = time.time()

    parser = argparse.ArgumentParser(description='Palo Alto Networks CDSS API Interface Class')

    # Required arguments which requires a parameter (eg. -d test)
    parser.add_argument(
        '-l',
        '--log',
        action='store',
        dest='log',
        help='name of log file to store output',
        required=True
    )

    # Add configuration file argument
    parser.add_argument(
        '-c',
        '--config',
        action='store',
        dest='config',
        help='name or path to the configuration.ini file',
        required=True
    )

    # Add verbose argument
    parser.add_argument(
        '-v',
        '--verbose',
        action='store_true',
        default=False,
        help='enable verbose logging output',
        required=False
    )

    # Add version output
    parser.add_argument(
        "--version",
        action="version",
        help='shows this applications version details and exits',
        version="%(prog)s {version}-{status}".format(version=__version__, status=__status__)
    )

    # Parse arguments
    args = parser.parse_args()

    # Check if verbose flag is set
    if args.verbose is True:
        level = logging.DEBUG
    else:
        level = logging.INFO

    # Create format handlers for logzero
    log_fmt_term = "%(color)s[%(asctime)s][%(funcName)s:%(lineno)d][%(levelname)s]%(end_color)s %(message)s"
    log_fmt_file = "[%(asctime)s][PID:%(process)d][%(funcName)s:%(lineno)d][%(levelname)s] %(message)s"

    fmt_term = logzero.LogFormatter(fmt=log_fmt_term, datefmt=date_format)
    fmt_file = logzero.LogFormatter(fmt=log_fmt_file, datefmt=date_format)
    logzero.formatter(fmt_term)

    # Configure the desired log level
    logzero.loglevel(level=level, update_custom_handlers=False)

    # Configure the logging file (16 Megabytes)
    logzero.logfile(args.log, formatter=fmt_file, maxBytes=16777216, backupCount=3, loglevel=level)

    # Read the configuration file
    log.debug(separator)
    log.debug('Starting new script instance...')
    config = exec_read_configuration(args.config)

    # Output details to the debug
    log.debug('Set script execution start time to: ' + str(start))
    log.debug('Parsed Arguments from runtime: ' + str(args))
    log.debug('Halt on error: ' + str(config.get('general', {}).get('halt_on_error', True)))

    # Cleanup setup variables
    del log_fmt_term
    del log_fmt_file
    del fmt_term
    del fmt_file
    del level

    # Handover to main()
    log.debug('Calling main()...')
    main()
